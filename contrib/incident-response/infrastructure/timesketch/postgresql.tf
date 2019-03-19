# Copyright 2019 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
  name              = "timesketch-db-instance-${random_id.infrastructure-random-id.hex}"
  region            = "${var.gcp_region}"
  database_version  = "POSTGRES_9_6"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      authorized_networks = {
        name  = "timesketch-server"
        value = "${google_compute_address.timesketch-server-address.address}"
      }
    }

    location_preference {
      zone = "${var.gcp_zone}"
    }
  }
}
