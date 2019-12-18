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

  project_id      = var.project_id
  org_id          = var.org_id
  domain          = var.domain
  forseti_version = var.forseti_version

  client_instance_metadata = {
    sshKeys = "ubuntu:${tls_private_key.main.public_key_openssh}"
  }
  server_instance_metadata = {
    sshKeys = "ubuntu:${tls_private_key.main.public_key_openssh}"
  }
}

resource "null_resource" "wait_for_client" {
  triggers = {
    always_run = uuid()
  }

  provisioner "remote-exec" {
    script = "${path.module}/scripts/wait-for-forseti.sh"

    connection {
      type                = "ssh"
      user                = "ubuntu"
      host                = module.forseti.forseti-client-vm-ip
      private_key         = tls_private_key.main.private_key_pem
      bastion_host        = module.bastion.host
      bastion_port        = module.bastion.port
      bastion_private_key = module.bastion.private_key
      bastion_user        = module.bastion.user
    }
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
# Forseti Server Rules
#-------------------------#
module "forseti_server_rules" {
  source                        = "./modules/rules"
  domain                        = var.domain
  forseti_server_storage_bucket = module.forseti.forseti-server-storage-bucket
  org_id                        = var.org_id
}

#-------------------------#
# Test Resources
#-------------------------#
module "test_resources" {
  source     = "./modules/test_resources"
  billing_account = var.billing_account
  org_id          = var.org_id
  project_id      = var.project_id
}

resource "google_bigquery_dataset" "scanner-test-bigquery-dataset" {
  dataset_id                  = "scanner_test"
  friendly_name               = "scanner_test"
  description                 = "dataset for testing scanner"
  project                     = var.project_id

  access {
    role          = "READER"
    special_group = "allAuthenticatedUsers"
  }
}
