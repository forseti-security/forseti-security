/**
* Copyright 2020 Google LLC
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

resource "random_id" "random_test_id" {
  byte_length = 8
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

  project_id               = var.project_id
  org_id                   = var.org_id
  domain                   = var.domain
  forseti_version          = var.forseti_version

  config_validator_enabled = var.config_validator_enabled

  # run the cron job every 10 so it does not run while tests are executing
  forseti_run_frequency    = "0 */10 * * *"

  inventory_email_summary_enabled = var.inventory_email_summary_enabled
  forseti_email_recipient = var.forseti_email_recipient
  forseti_email_sender = var.forseti_email_sender
  sendgrid_api_key = var.sendgrid_api_key

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
    inline = [
      "until [ -f /home/ubuntu/forseti-security/configs/forseti_conf_client.yaml ]; do sleep 5; done; echo Forseti client startup complete;",
    ]

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
    inline = [
      "until [ -f /home/ubuntu/forseti_env.sh ]; do sleep 5; done; echo Forseti server startup complete;",
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
# Forseti IAM
#-------------------------#
module "forseti_iam" {
  source                         = "./modules/forseti_iam"
  forseti_server_service_account = module.forseti.forseti-server-service-account
  project_id                     = var.project_id
  random_test_id                 = random_id.random_test_id.hex
}

#-------------------------#
# Forseti Rules
#-------------------------#
module "forseti_server_rules" {
  source                         = "./modules/rules"
  domain                         = var.domain
  forseti_server_service_account = module.forseti.forseti-server-service-account
  forseti_server_storage_bucket  = module.forseti.forseti-server-storage-bucket
  org_id                         = var.org_id
  project_id                     = var.project_id
}

#-------------------------#
# Policy Library GCS
#-------------------------#
module "policy_library" {
  source                        = "./modules/policy_library"
  forseti_server_storage_bucket = module.forseti.forseti-server-storage-bucket
}

#-------------------------#
# Test Resources
#-------------------------#
module "test_resources" {
  source                         = "./modules/test_resources"
  billing_account                = var.billing_account
  forseti_server_service_account = module.forseti.forseti-server-service-account
  org_id                         = var.org_id
  project_id                     = var.project_id
  random_test_id                 = random_id.random_test_id.hex
}
