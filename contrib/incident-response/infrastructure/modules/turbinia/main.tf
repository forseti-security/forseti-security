/**
 * Copyright 2019 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

locals {
  # API services to enable for the project
  services_list = [
    "compute.googleapis.com",
    "datastore.googleapis.com",
    "iam.googleapis.com",
    "pubsub.googleapis.com",
    "storage-component.googleapis.com"
  ]
}

resource "google_project_service" "services" {
  count              = length(local.services_list)
  project            = var.gcp_project
  service            = local.services_list[count.index]
  disable_on_destroy = false
}

# Enable PubSub and create topic
resource "google_pubsub_topic" "pubsub-topic" {
  name = "turbinia-${var.infrastructure_id}"
  depends_on  = [google_project_service.services]
}

resource "google_pubsub_topic" "pubsub-topic-psq" {
  name        = "turbinia-${var.infrastructure_id}-psq"
  depends_on  = [google_project_service.services]
}

# Cloud Storage Bucket
resource "google_storage_bucket" "output-bucket" {
  name          = "turbinia-${var.infrastructure_id}"
  depends_on    = [google_project_service.services]
  force_destroy = true
}

# Bucket notfication for GCS importer
resource "google_pubsub_topic" "pubsub-topic-gcs" {
  name = "turbinia-gcs"
  depends_on  = [google_project_service.services]
}

data "google_storage_project_service_account" "gcs-pubsub-account" {
}

resource "google_pubsub_topic_iam_binding" "binding" {
  topic   = google_pubsub_topic.pubsub-topic-gcs.id
  role    = "roles/pubsub.publisher"
  members = ["serviceAccount:${data.google_storage_project_service_account.gcs-pubsub-account.email_address}"]
}

resource "google_storage_notification" "notification" {
  bucket         = google_storage_bucket.output-bucket.name
  payload_format = "JSON_API_V1"
  topic          = google_pubsub_topic.pubsub-topic-gcs.id
  event_types    = ["OBJECT_FINALIZE", "OBJECT_METADATA_UPDATE"]
  custom_attributes = {
    new-attribute = "new-attribute-value"
  }
  depends_on = [google_pubsub_topic_iam_binding.binding]
}

resource "google_pubsub_subscription" "gcs-subscription" {
  name  = "gcs-subscription"
  topic = google_pubsub_topic.pubsub-topic-gcs.name
  message_retention_duration = "1200s"
  retain_acked_messages      = true
  ack_deadline_seconds = 20
  expiration_policy {
    ttl = "300000.5s"
  }
}

# Create datastore index
data "local_file" "datastore-index-file" {
  filename = "${path.module}/data/index.yaml"
  depends_on  = [google_project_service.services]
}

resource "null_resource" "cloud-datastore-create-index" {
  provisioner "local-exec" {
    command = "gcloud -q datastore indexes create ${data.local_file.datastore-index-file.filename} --project=${var.gcp_project}"
  }
}

# Template for systemd service file
data "template_file" "turbinia-systemd" {
  template = file("${path.module}/templates/turbinia.service.tpl")
}

# Turbinia config
data "template_file" "turbinia-config-template" {
  template = file("${path.module}/templates/turbinia.conf.tpl")
  vars = {
    project           = var.gcp_project
    region            = var.gcp_region
    zone              = var.gcp_zone
    turbinia_id       = var.infrastructure_id
    pubsub_topic      = google_pubsub_topic.pubsub-topic.name
    pubsub_topic_psq  = google_pubsub_topic.pubsub-topic-psq.name
    bucket            = google_storage_bucket.output-bucket.name
  }
  depends_on  = [google_project_service.services]
}

# Turbinia server
data "template_file" "turbinia-server-startup-script" {
  template = file("${path.module}/templates/scripts/install-turbinia-server.sh.tpl")
  vars = {
    config = data.template_file.turbinia-config-template.rendered
    systemd = data.template_file.turbinia-systemd.rendered
    pip_source = var.turbinia_pip_source
  }
}

resource "google_compute_instance" "turbinia-server" {
  name         = "turbinia-server-${var.infrastructure_id}"
  machine_type = var.turbinia_server_machine_type
  zone         = var.gcp_zone
  depends_on   = [google_project_service.services, google_pubsub_topic.pubsub-topic, google_pubsub_topic.pubsub-topic-psq]

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = var.gcp_ubuntu_1804_image
      size  = var.turbinia_server_disk_size_gb
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config {}
  }

  service_account {
    scopes = ["compute-ro", "storage-rw", "pubsub", "datastore"]
  }

  lifecycle {
    ignore_changes = [metadata_startup_script]
  }

  # Provision the machine with a script.
  metadata_startup_script = data.template_file.turbinia-server-startup-script.rendered
}

# Turbinia worker
data "template_file" "turbinia-worker-startup-script" {
  template = file("${path.module}/templates/scripts/install-turbinia-worker.sh.tpl")
  vars = {
    config = data.template_file.turbinia-config-template.rendered
    systemd = data.template_file.turbinia-systemd.rendered
    pip_source = var.turbinia_pip_source
  }
}

resource "google_compute_instance" "turbinia-worker" {
  count        = var.turbinia_worker_count
  name         = "turbinia-worker-${var.infrastructure_id}-${count.index}"
  machine_type = var.turbinia_worker_machine_type
  zone         = var.gcp_zone
  depends_on   = [google_project_service.services, google_compute_instance.turbinia-server]

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = var.gcp_ubuntu_1804_image
      size  = var.turbinia_worker_disk_size_gb
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config {}
  }

  service_account {
    scopes = ["compute-rw", "storage-rw", "pubsub", "datastore", "cloud-platform"]
  }

  lifecycle {
    ignore_changes = [metadata_startup_script]
  }

  # Provision the machine with a script.
  metadata_startup_script = data.template_file.turbinia-worker-startup-script.rendered
}
