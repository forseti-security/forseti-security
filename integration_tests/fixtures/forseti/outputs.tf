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

output "bastion_host" {
  value = module.bastion.host
}

output "forseti-cai-storage-bucket" {
  description = "Forseti CAI storage bucket"
  value       = module.forseti.forseti-cai-storage-bucket
}

output "forseti-client-vm-ip" {
  description = "Forseti Client VM private IP address"
  value       = module.forseti.forseti-client-vm-ip
}

output "forseti-client-vm-name" {
  description = "Forseti Client VM name"
  value       = module.forseti.forseti-client-vm-name
}

output "forseti-client-service-account" {
  description = "Forseti Client service account"
  value       = module.forseti.forseti-client-service-account
}

output "forseti-client-storage-bucket" {
  description = "Forseti Client storage bucket"
  value       = module.forseti.forseti-client-storage-bucket
}

output "forseti-cloudsql-password" {
  description = "CloudSQL password"
  value       = module.forseti.forseti-cloudsql-password
  sensitive   = true
}

output "forseti-cloudsql-user" {
  description = "CloudSQL user"
  value       = module.forseti.forseti-cloudsql-user
}

output "forseti-server-vm-ip" {
  description = "Forseti Server VM private IP address"
  value       = module.forseti.forseti-server-vm-ip
}

output "forseti-server-vm-name" {
  description = "Forseti Server VM name"
  value       = module.forseti.forseti-server-vm-name
}

output "forseti-server-service-account" {
  description = "Forseti Server service account"
  value       = module.forseti.forseti-server-service-account
}

output "forseti-server-storage-bucket" {
  description = "Forseti Server storage bucket"
  value       = module.forseti.forseti-server-storage-bucket
}

output "kms_resources_names" {
  description = "Forseti KMS resources"
  value       = module.test_resources.kms_resources_names
}

output "org_id" {
  description = "A forwarded copy of `org_id` for InSpec"
  value       = var.org_id
}

output "project_id" {
  description = "A forwarded copy of `project_id` for InSpec"
  value       = var.project_id
}

output "suffix" {
  description = "The random suffix appended to Forseti resources"
  value       = module.forseti.suffix
}

# Test Resources
output "bucket_acl_scanner_bucket_name" {
  description = "Bucket name created for the Bucket ACL Scanner test"
  value = module.test_resources.bucket_acl_scanner_bucket_name
}

output "random_test_id" {
  description = "Random test id generated every time the tests are run"
  value       = module.test_resources.random_test_id
}
