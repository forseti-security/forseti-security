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
  description = "Config Validator scanner enabled"
  default     = true
}

variable "domain" {
  description = "GCP Organization domain details that will be used for integration tests"
}

variable "forseti_version" {
  description = "The version of Forseti to deploy"
  default = "master"
}

variable "gsuite_admin_email" {
  description = "The email of a GSuite super admin, used for pulling user directory information *and* sending notifications."
}

variable "org_id" {
  description = "GCP Organization ID that Forseti will have purview over"
}

variable "project_id" {
  description = "The ID of an existing Google project where Forseti will be installed"
}
