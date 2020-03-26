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

output "bucket_acl_scanner_all_auth_bucket_name" {
  description = "Bucket name created for the Bucket ACL Scanner all auth test"
  value = google_storage_bucket.bucket_acl_scanner_all_auth.name
}

output "bucket_acl_scanner_all_users_bucket_name" {
  description = "Bucket name created for the Bucket ACL Scanner all user test"
  value = google_storage_bucket.bucket_acl_scanner_all_users.name
}

output "enforcer_allow_all_icmp_rule_name" {
  description = "Firewall rule name created for the Firewall Enforcer test"
  value = google_compute_firewall.enforcer_allow_all_icmp_rule.name
}

output "firewall-allow-all-ingress-name" {
  description = "Firewall rule name created for the firewall scanner test"
  value       = google_compute_firewall.firewall_allow_all_ingress.name
}

output "inventory-cai-eu-bucket-name" {
  description = "Bucket name of EU bucket create for the the Inventory CAI Enabled vs Disabled test"
  value = google_storage_bucket.inventory_cai_eu.name
}
