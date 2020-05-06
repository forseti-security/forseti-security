/**
 * Copyright 2020 The Forseti Security Authors. All rights reserved.
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

variable "domain" {
  description = "The domain associated with the GCP Organization ID"
}

variable "forseti_server_service_account" {
  description = "Forseti Server service account"
}

variable "forseti_server_storage_bucket" {
  description = "The Forseti Server GCS bucket name"
}

variable "org_id" {
  description = "The organization ID"
}

variable "project_id" {
  description = "The organization ID"
}
