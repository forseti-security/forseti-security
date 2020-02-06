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

variable "gcp_project" {
  description = "Name of the Google Cloud project to deploy to"
}

variable "gcp_region" {
  description = "GCP region to create resources in"
  default     = "australia-southeast1"
}

variable "gcp_zone" {
  description = "GCP zone to create resources in"
  default     = "australia-southeast1"
}

variable "appengine_location" {
  description = "Location for AppEngine and Datastore"
  default     = "australia-southeast1"
}

variable "gcp_ubuntu_1804_image" {
  description = "Ubuntu version 18.04 image"
  default     = "ubuntu-os-cloud/ubuntu-1804-lts"
}

variable "infrastructure_id" {
  description = "Unique indentifier for the deployment"
}

variable "turbinia_server_machine_type" {
  description = "Machine type for Turbinia server"
  default     = "n1-standard-2"
}

variable "turbinia_worker_machine_type" {
  description = "Machine type for Turbinia worker."
  default     = "n1-standard-16"
}

variable "turbinia_server_disk_size_gb" {
  description = "Disk size for Turbinia server machine."
  default     = 200
}

variable "turbinia_worker_disk_size_gb" {
  description = "Disk size for Turbinia worker machine."
  default     = 200
}

variable "turbinia_worker_count" {
  description = "Number of Turbinia worker machines to run."
  default     = 2
}

variable "turbinia_pip_source" {
  description = "Source package to use for Pip."
  default     = "turbinia"
}
