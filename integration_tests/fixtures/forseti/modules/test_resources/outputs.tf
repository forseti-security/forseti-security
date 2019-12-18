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

output "bucket_acl_scanner_bucket_name" {
  description = "Bucket name created for the Bucket ACL Scanner test"
  value = google_storage_bucket.bucket_acl_scanner.name
}

output "enforcer_allow_all_icmp_rule_name" {
  description = "Firewall rule name created for the Firewall Enforcer test"
  value = google_compute_firewall.enforcer_allow_all_icmp_rule.name
}

output "kms_resources_names" {
  description = "KMS resources for Inventory tests"
  value       = [
    google_kms_key_ring.test-keyring.name,
    google_kms_crypto_key.test-crypto-key.name,
  ]
}

output "random_test_id" {
  description = "Random test id generated every time the tests are run"
  value       = random_id.random_test_id.hex
}
