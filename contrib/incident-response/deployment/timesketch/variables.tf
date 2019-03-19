# Variables that needs input frmo the user
variable "gcp_project" {
  description = "Name of your cloud project"
}

variable "gcp_region" {
  description = "GCP region to create resources in"
}

variable "gcp_zone"                         {
  description = "GCP zone to create resources in"
}

# Default variables
variable "gcp_ubuntu_1804_image" {
  default = "ubuntu-os-cloud/ubuntu-1804-lts"
}

# Timesketch variables
variable "timesketch_machine_type" {
  default = "n1-standard-2"
}
variable "timesketch_disk_size_gb" {
  default = 200
}
variable "timesketch_admin_username" {
  default = "admin"
}

# Elasticsearch variables
variable "elasticsearch_cluster_name" {
  default = "timesketch"
}
variable "elasticsearch_machine_type" {
  default = "n1-highmem-4"
}
variable "elasticsearch_disk_size_gb" {
  default = 200
}
variable "elasticsearch_node_count" {
  default = 2
}
