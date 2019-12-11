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

resource "random_id" "random_test_id" {
  byte_length = 8
}

resource "random_pet" "random_name_generator" {
}

#-------------------------#
# inventory-create.rb: Create KMS resources for inventory testing
#-------------------------#
resource "google_kms_key_ring" "test-keyring" {
  project  = var.project_id
  name     = "keyring-${random_pet.random_name_generator.id}"
  location = "global"
}

resource "google_kms_crypto_key" "test-crypto-key" {
  name            = "crypto-key-${random_pet.random_name_generator.id}"
  key_ring        = google_kms_key_ring.test-keyring.self_link
  rotation_period = "100000s"
}

#-------------------------#
# scanner-bucket_acl_scanner.rb: Create a bucket with AllAuth + All Users Reader ACL
#-------------------------#
resource "google_storage_bucket" "bucket_acl_scanner" {
  name     = "foresti-test-bucket-${random_id.random_test_id.hex}"
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
