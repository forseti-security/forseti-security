/**
*   Copyright 2019 Google LLC
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

variable "billing_account" {
  description = "GCP Organization billing account details"
}

variable "config_validator_enabled" {
  description = "Enable Config Validator scanner"
  default     = true
}

variable "domain" {
  description = "GCP Organization domain details that will be used for integration tests"
}

variable "forseti_version" {
  description = "The version of Forseti to deploy"
  default     = "master"
}

variable "forseti_email_recipient" {
  description = "Email address that receives Forseti notifications"
  default     = ""
}

variable "forseti_email_sender" {
  description = "Email address that sends the Forseti notifications"
  default     = ""
}

variable "gsuite_admin_email" {
  description = "The email of a GSuite super admin, used for pulling user directory information *and* sending notifications."
}

variable "inventory_email_summary_enabled" {
  description = "Email summary for inventory enabled"
  default     = false
}

variable "inventory_performance_cai_dump_paths" {
  description = "GCS paths of the CAI dump files to be used for the inventory performance test"
}

variable "kms_key" {
  description = "KMS key to be used for encrypting/decrypting test resources"
}

variable "kms_keyring" {
  description = "KMS keyring to be used for encrypting/decrypting test resources"
}

variable "org_id" {
  description = "GCP Organization ID that Forseti will have purview over"
}

variable "project_id" {
  description = "The ID of an existing Google project where Forseti will be installed"
}

variable "sendgrid_api_key" {
  description = "Sendgrid.com API key to enable email notifications"
  default     = ""
}
