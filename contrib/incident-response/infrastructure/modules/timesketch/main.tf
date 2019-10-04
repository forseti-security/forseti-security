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

#-----------------------#
# Elasticsearch cluster #
#-----------------------#
data "template_file" "elasticsearch-startup-script" {
  template = "${file("${path.module}/templates/scripts/install-elasticsearch.sh.tpl")}"

  vars = {
    cluster_name  = "${var.elasticsearch_cluster_name}"
    project       = "${var.gcp_project}"
    zone          = "${var.gcp_zone}"
  }
}

resource "google_compute_instance" "elasticsearch" {
  count        = "${var.elasticsearch_node_count}"
  name         = "elasticsearch-node-${var.infrastructure_id}-${count.index}"
  machine_type = "${var.elasticsearch_machine_type}"
  zone         = "${var.gcp_zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.gcp_ubuntu_1804_image}"
      size  = "${var.elasticsearch_disk_size_gb}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config {}
  }

  # Tag for service enumeration.
  tags = ["elasticsearch"]

  # Enable the GCE discovery module to call required APIs.
  service_account {
    scopes = ["compute-ro"]
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.elasticsearch-startup-script.rendered}"
}

#------------#
# PostgreSQL #
#------------#

# Enable Google Cloud SQL admin API for the project.
resource "google_project_service" "sql-admin-service-api" {
  project   = "${var.gcp_project}"
  service   = "sqladmin.googleapis.com"
}

resource "google_sql_database" "timesketch-db" {
  name     = "timesketch-db"
  instance = "${google_sql_database_instance.timesketch-db-instance.name}"
}

resource "google_sql_user" "timesketch-db-user" {
  name     = "timesketch"
  instance = "${google_sql_database_instance.timesketch-db-instance.name}"
  password = "${random_string.timesketch-db-password.result}"
}

resource "random_string" "timesketch-db-password" {
  length = 16
  special = false
}

resource "google_sql_database_instance" "timesketch-db-instance" {
  name              = "timesketch-db-instance-${var.infrastructure_id}"
  region            = "${var.gcp_region}"
  database_version  = "POSTGRES_9_6"
  depends_on        = ["google_project_service.sql-admin-service-api"]

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      require_ssl  = false
      authorized_networks {
        name  = "timesketch-server"
        value = "${google_compute_address.timesketch-server-address.address}"
      }
    }

    location_preference {
      zone = "${var.gcp_zone}"
    }
  }
}

#-------#
# Redis #
#-------#

# Enable Google Cloud Resource Manager API for the project.
resource "google_project_service" "cloud-resource-service-api" {
  project   = "${var.gcp_project}"
  service   = "cloudresourcemanager.googleapis.com"
}

# Enable Google Cloud Memorystore for Redis API for the project.
resource "google_project_service" "redis-service-api" {
  project     = "${var.gcp_project}"
  service     = "redis.googleapis.com"
  depends_on  = ["google_project_service.cloud-resource-service-api"]
}

# Redis is used as the task queue backend for importing data into Timesketch.
resource "google_redis_instance" "redis" {
  name           = "redis-${var.infrastructure_id}"
  memory_size_gb = 1
  depends_on     = ["google_project_service.redis-service-api"]
}

#-------------------#
# Timesketch server #
#-------------------#
data "template_file" "timesketch-server-startup-script" {
  template = "${file("${path.module}/templates/scripts/install-timesketch.sh.tpl")}"
  vars = {
    timesketch_admin_username = "${var.timesketch_admin_username}"
    timesketch_admin_password = "${random_string.timesketch-admin-password.result}"
    elasticsearch_node        = "${google_compute_instance.elasticsearch.*.name[0]}"
    postgresql_host           = "${google_sql_database_instance.timesketch-db-instance.ip_address.0.ip_address}"
    postgresql_db_name        = "${google_sql_database.timesketch-db.name}"
    postgresql_user           = "${google_sql_user.timesketch-db-user.name}"
    postgresql_password       = "${random_string.timesketch-db-password.result}"
    redis_host                = "${google_redis_instance.redis.host}"
    redis_port                = "${google_redis_instance.redis.port}"
  }
}

resource "random_string" "timesketch-admin-password" {
  length = 16
  special = false
}

resource "google_compute_address" "timesketch-server-address" {
  name = "timesketch-server-address"
}

resource "google_compute_firewall" "allow-external-timesketch-server" {
  name    = "allow-external-timesketch-https-server"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["443"]
  }
  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["timesketch-https-server"]
}

resource "google_compute_instance" "timesketch-server" {
  name          = "timesketch-server-${var.infrastructure_id}"
  machine_type  = "${var.timesketch_machine_type}"
  zone          = "${var.gcp_zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.gcp_ubuntu_1804_image}"
      size  = "${var.timesketch_disk_size_gb}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"

    access_config {
      nat_ip = "${google_compute_address.timesketch-server-address.address}"
    }
  }

  service_account {
    scopes = ["storage-ro", "pubsub"]
  }

  # Allow HTTPS traffic
  tags = ["timesketch-https-server", "https-server"]

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.timesketch-server-startup-script.rendered}"
}