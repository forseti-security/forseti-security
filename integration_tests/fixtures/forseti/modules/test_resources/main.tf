/**
* Copyright 2019 Google LLC
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

#-------------------------#
# enforcer-remediates_non_compliant_rule.rb: Create a firewall rule to test it gets removed
#-------------------------#
resource "google_compute_firewall" "enforcer_allow_all_icmp_rule" {
  name                    = "forseti-server-allow-icmp-${var.random_test_id}"
  project                 = var.project_id
  network                 = "default"
  priority                = "100"
  source_ranges           = ["10.0.0.0/32"]

  allow {
    protocol = "icmp"
  }
}

#-------------------------#
# inventory-cai_enabled_vs_disabled.rb: Create a bucket in the EU
#-------------------------#
resource "google_storage_bucket" "inventory_cai_eu" {
  name     = "foresti-test-bucket-eu-${var.random_test_id}"
  project  = var.project_id
  location = "EU"
}

resource "google_storage_bucket_access_control" "inventory_cai_eu_acl" {
  bucket = google_storage_bucket.bucket_acl_scanner.name
  role   = "READER"
  entity = "user-${var.forseti_server_service_account}"

  depends_on = [google_storage_bucket.inventory_cai_eu]
}

#-------------------------#
# scanner-bucket_acl_scanner.rb: Create a bucket with AllAuth + All Users Reader ACL
#-------------------------#
resource "google_storage_bucket" "bucket_acl_scanner" {
  name     = "foresti-test-bucket-${var.random_test_id}"
  project  = var.project_id
  location = "US"
}

resource "google_storage_bucket_access_control" "bucket_acl_scanner_all_auth_acl" {
  bucket = google_storage_bucket.bucket_acl_scanner.name
  role   = "READER"
  entity = "allAuthenticatedUsers"

  depends_on = [google_storage_bucket.bucket_acl_scanner]
}

resource "google_storage_bucket_access_control" "bucket_acl_scanner_all_users_acl" {
  bucket = google_storage_bucket.bucket_acl_scanner.name
  role   = "READER"
  entity = "allUsers"

  depends_on = [
    google_storage_bucket.bucket_acl_scanner,
    google_storage_bucket_access_control.bucket_acl_scanner_all_auth_acl
  ]
}
