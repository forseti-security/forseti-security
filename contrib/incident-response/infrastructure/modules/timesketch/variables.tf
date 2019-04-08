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
  default     = "us-central1"
}

variable "gcp_zone" {
  description = "GCP zone to create resources in"
  default     = "us-central1-f"
}

variable "gcp_ubuntu_1804_image" {
  description = "Ubuntu version 18.04 image"
  default     = "ubuntu-os-cloud/ubuntu-1804-lts"
}

variable "timesketch_machine_type" {
  description = "Machine type for Timesketch server"
  default     = "n1-standard-2"
}

variable "timesketch_disk_size_gb" {
  description = "Disk size for Timesketch server root disk"
  default     = 200
}

variable "timesketch_admin_username" {
  description = "Timesketch admin user"
  default     = "admin"
}

variable "elasticsearch_cluster_name" {
  description = "Name of the Elasticsearch cluster"
  default     = "timesketch"
}

variable "elasticsearch_machine_type" {
  description = "Machine type for Elastichsearch cluster machines"
  default     = "n1-highmem-4"
}

variable "elasticsearch_disk_size_gb" {
  description = "Disk size for Elasticsearch cluster machines."
  default     = 1024
}

variable "elasticsearch_node_count" {
  description = "Number of Elasticsearch cluster machines"
  default     = 2
}
