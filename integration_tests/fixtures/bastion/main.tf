/**
 * Copyright 2018 Google LLC
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
  user = "ubuntu"
}

resource "tls_private_key" "main" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "main" {
  content  = "${tls_private_key.main.private_key_pem}"
  filename = "${path.module}/tls_private_key"
}

resource "random_pet" "main" {
  length    = 1
  prefix    = "forseti-test-bastion"
  separator = "-"
}

data "google_compute_image" "main" {
  family  = "ubuntu-minimal-1804-lts"
  project = "ubuntu-os-cloud"
}

resource "google_compute_instance" "main" {
  boot_disk {
    initialize_params {
      image = "${data.google_compute_image.main.self_link}"
    }
  }

  machine_type = "f1-micro"
  name         = "${random_pet.main.id}"
  zone         = "${var.zone}"

  network_interface {
    subnetwork         = "${var.subnetwork}"
    subnetwork_project = "${var.project_id}"

    access_config {}
  }

  metadata = {
    sshKeys = "${local.user}:${tls_private_key.main.public_key_openssh}"
  }

  project = "${var.project_id}"
  tags    = ["bastion"]
}

resource "google_compute_firewall" "main" {
  name    = "${random_pet.main.id}"
  network = "${var.network}"

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  direction     = "INGRESS"
  priority      = "100"

  # Setting source range to Travis netblocks defined here: https://docs.travis-ci.com/user/ip-addresses/
  source_ranges = ["${var.firewall_netblocks}"]
  
  target_tags   = ["bastion"]
  project       = "${var.project_id}"
}

