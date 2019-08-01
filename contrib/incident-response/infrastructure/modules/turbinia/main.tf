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

# Random ID for creating unique resource names.
resource "random_id" "infrastructure-random-id" {
  byte_length = 8
}

# Enable GCP services individually.
resource "google_project_service" "cloudfunctions" {
  project = "${var.gcp_project}"
  service = "cloudfunctions.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "compute" {
  project = "${var.gcp_project}"
  service = "compute.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "datastore" {
  project = "${var.gcp_project}"
  service = "datastore.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project = "${var.gcp_project}"
  service = "iam.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "pubsub" {
  project = "${var.gcp_project}"
  service = "pubsub.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "storage-component" {
  project = "${var.gcp_project}"
  service = "storage-component.googleapis.com"
  disable_on_destroy = false
}

# Enable PubSub and create topic
resource "google_pubsub_topic" "pubsub-topic" {
  name = "turbinia-${random_id.infrastructure-random-id.hex}"
  depends_on  = ["google_project_service.pubsub"]
}

resource "google_pubsub_topic" "pubsub-topic-psq" {
  name        = "turbinia-${random_id.infrastructure-random-id.hex}-psq"
  depends_on  = ["google_project_service.pubsub"]
}

# Cloud Storage Bucket
resource "google_storage_bucket" "output-bucket" {
  name          = "turbinia-${random_id.infrastructure-random-id.hex}"
  depends_on    = ["google_project_service.storage-component"]
  force_destroy = true
}

# Create datastore index
data "local_file" "datastore-index-file" {
  filename = "${path.module}/data/index.yaml"
  depends_on  = ["google_project_service.datastore"]
}

resource "null_resource" "cloud-datastore-create-index" {
  provisioner "local-exec" {
    command = "gcloud -q datastore indexes create ${data.local_file.datastore-index-file.filename} --project=${var.gcp_project}"
  }
}

# Deploy cloud functions
data "archive_file" "cloudfunction-archive" {
  type        = "zip"
  output_path = "${path.module}/data/function.zip"

  source {
    content  = "${file("${path.module}/data/function.js")}"
    filename = "function.js"
  }

  source {
    content  = "${file("${path.module}/data/package.json")}"
    filename = "package.json"
  }
}

resource "google_storage_bucket_object" "cloudfunction-archive" {
  name   = "function.zip"
  bucket = "${google_storage_bucket.output-bucket.name}"
  source = "${path.module}/data/function.zip"
  depends_on = ["data.archive_file.cloudfunction-archive"]
}

resource "google_cloudfunctions_function" "gettasks" {
    name                      = "gettasks"
    entry_point               = "gettasks"
    available_memory_mb       = 256
    timeout                   = 60
    runtime                   = "nodejs8"
    project                   = "${var.gcp_project}"
    region                    = "${var.gcp_region}"
    trigger_http              = true
    source_archive_bucket     = "${google_storage_bucket.output-bucket.name}"
    source_archive_object     = "${google_storage_bucket_object.cloudfunction-archive.name}"
}

resource "google_cloudfunctions_function" "closetasks" {
    name                      = "closetasks"
    entry_point               = "closetasks"
    available_memory_mb       = 256
    timeout                   = 60
    runtime                   = "nodejs8"
    project                   = "${var.gcp_project}"
    region                    = "${var.gcp_region}"
    trigger_http              = true
    source_archive_bucket     = "${google_storage_bucket.output-bucket.name}"
    source_archive_object     = "${google_storage_bucket_object.cloudfunction-archive.name}"
}

resource "google_cloudfunctions_function" "closetask" {
    name                      = "closetask"
    entry_point               = "closetask"
    available_memory_mb       = 256
    timeout                   = 60
    runtime                   = "nodejs8"
    project                   = "${var.gcp_project}"
    region                    = "${var.gcp_region}"
    trigger_http              = true
    source_archive_bucket     = "${google_storage_bucket.output-bucket.name}"
    source_archive_object     = "${google_storage_bucket_object.cloudfunction-archive.name}"
}

# Template for systemd service file
data "template_file" "turbinia-systemd" {
  template = "${file("${path.module}/templates/turbinia.service.tpl")}"
}

# Turbinia config
data "template_file" "turbinia-config-template" {
  template = "${file("${path.module}/templates/turbinia.conf.tpl")}"
  vars = {
    project           = "${var.gcp_project}"
    region            = "${var.gcp_region}}"
    zone              = "${var.gcp_zone}"
    turbinia_id       = "${random_id.infrastructure-random-id.hex}"
    pubsub_topic      = "${google_pubsub_topic.pubsub-topic.name}"
    pubsub_topic_psq  = "${google_pubsub_topic.pubsub-topic-psq.name}"
    bucket            = "${google_storage_bucket.output-bucket.name}"
  }
  depends_on  = ["google_project_service.datastore"]
}

# Turbinia server
data "template_file" "turbinia-server-startup-script" {
  template = "${file("${path.module}/templates/scripts/install-turbinia-server.sh.tpl")}"
  vars = {
    config = "${data.template_file.turbinia-config-template.rendered}"
    systemd = "${data.template_file.turbinia-systemd.rendered}"
  }
}

resource "google_compute_instance" "turbinia-server" {
  name         = "turbinia-server"
  machine_type = "${var.turbinia_server_machine_type}"
  zone         = "${var.gcp_zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.gcp_ubuntu_1804_image}"
      size  = "${var.turbinia_server_disk_size_gb}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config {}
  }

  service_account {
    scopes = ["compute-ro", "storage-rw", "pubsub"]
  }

  lifecycle {
    ignore_changes = ["metadata_startup_script"]
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.turbinia-server-startup-script.rendered}"
}

# Turbinia worker
data "template_file" "turbinia-worker-startup-script" {
  template = "${file("${path.module}/templates/scripts/install-turbinia-worker.sh.tpl")}"
  vars = {
    config = "${data.template_file.turbinia-config-template.rendered}"
    systemd = "${data.template_file.turbinia-systemd.rendered}"
  }
}

resource "google_compute_instance" "turbinia-worker" {
  count        = "${var.turbinia_worker_count}"
  name         = "turbinia-worker-${count.index}"
  machine_type = "${var.turbinia_worker_machine_type}"
  zone         = "${var.gcp_zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.gcp_ubuntu_1804_image}"
      size  = "${var.turbinia_worker_disk_size_gb}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config {}
  }

  service_account {
    scopes = ["compute-ro", "storage-rw", "pubsub"]
  }

  lifecycle {
    ignore_changes = ["metadata_startup_script"]
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.turbinia-worker-startup-script.rendered}"
}
