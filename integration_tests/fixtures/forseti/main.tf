/**
* Copyright 2019 Google LLC
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*      http://www.apache.org/licenses/LICENSE-2.0
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/

provider "google-beta" {
  version     = "~> 2.10"
}

provider "tls" {
  version = "~> 2.0"
}

#-------------------------#
# Bastion Host
#-------------------------#
resource "tls_private_key" "main" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "local_file" "gce-keypair-pk" {
  content  = tls_private_key.main.private_key_pem
  filename = "${path.module}/sshkey"
}

module "bastion" {
  source = "../bastion"

  network    = "default"
  project_id = var.project_id
  subnetwork = "default"
  zone       = "us-central1-f"
}

#-------------------------#
# Forseti
#-------------------------#
module "forseti" {
  source = "git::github.com/forseti-security/terraform-google-forseti"

  project_id         = var.project_id
  org_id             = var.org_id
  domain             = var.domain
  forseti_version    = var.forseti_version

  client_instance_metadata = {
    sshKeys = "ubuntu:${tls_private_key.main.public_key_openssh}"
  }
  server_instance_metadata = {
    sshKeys = "ubuntu:${tls_private_key.main.public_key_openssh}"
  }
}

resource "null_resource" "wait_for_server" {
  triggers = {
    always_run = uuid()
  }

  provisioner "remote-exec" {
    script = "${path.module}/scripts/wait-for-forseti.sh"

    connection {
      type                = "ssh"
      user                = "ubuntu"
      host                = module.forseti.forseti-server-vm-ip
      private_key         = tls_private_key.main.private_key_pem
      bastion_host        = module.bastion.host
      bastion_port        = module.bastion.port
      bastion_private_key = module.bastion.private_key
      bastion_user        = module.bastion.user
    }
  }
}

resource "null_resource" "install-mysql-client" {
  triggers = {
    always_run = uuid()
  }

  provisioner "remote-exec" {
    inline = [
       "sudo apt-get update && sudo apt-get -y install mysql-client-5.7"
    ]

    connection {
      type                = "ssh"
      user                = "ubuntu"
      host                = module.forseti.forseti-server-vm-ip
      private_key         = tls_private_key.main.private_key_pem
      bastion_host        = module.bastion.host
      bastion_port        = module.bastion.port
      bastion_private_key = module.bastion.private_key
      bastion_user        = module.bastion.user
    }
  }

  depends_on = [null_resource.wait_for_server]
}

#-------------------------#
# Test Resources
#-------------------------#
resource "random_pet" "random_name_generator" {
}

resource "random_id" "random_id" {
  byte_length = 4
}

resource "google_kms_key_ring" "test-keyring" {
  project  = var.project_id
  name     = "keyring-${random_pet.random_name_generator.id}"
  location = "global"
}

resource "google_kms_crypto_key" "test-crypto-key" {
  name            = "crypto-key-${random_pet.random_name_generator.id}"
  key_ring        = google_kms_key_ring.test-keyring.self_link
  rotation_period = "100000s"
}

# enforcer-remediates_non_compliant_rule.rb: Create a firewall rule to be removed by FW Enforcer
# describe command("gcloud compute firewall-rules create forseti-test-allow-icmp-deleteme-#{random_string} --source-ranges=10.0.0.0/32 --description=\"Allow ICMP from private subnet\" --allow=icmp") do
resource "google_compute_firewall" "test_resource_forseti_server_allow_icmp" {
  name                    = "forseti-server-allow-icmp-${random_id.random_id.hex}"
  project                 = var.project_id
  network                 = "default"
  priority                = "100"
  source_ranges           = ["10.0.0.0/32"]

  allow {
    protocol = "icmp"
  }

  depends_on = [module.forseti]
}

# scanner-bucket_scanner.rb: Create a bucket with AllAuth Reader ACL
resource "google_storage_bucket" "test_resource_bucket_scanner_bucket" {
  name     = "foresti-test-bucket-${random_pet.random_name_generator.id}"
  project  = var.project_id
  location = "US"
}

resource "google_storage_bucket_access_control" "test_resource_bucket_scanner_bucket_acl" {
  bucket = google_storage_bucket.test_resource_bucket_scanner_bucket.name
  role   = "READER"
  entity = "allAuthenticatedUsers"

  depends_on = [google_storage_bucket.test_resource_bucket_scanner_bucket]
}
