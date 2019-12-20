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

locals {
  files = [
    "constraints/cloudsql_location.yaml",
    "constraints/compute_zone.yaml",
  ]
}

data "template_file" "constraints" {
  count = length(local.files)
  template = file(
    "${path.module}/templates/${element(local.files, count.index)}",
  )
}

resource "google_storage_bucket_object" "main" {
  count   = length(local.files)
  name    = "policy-library/policies/${element(local.files, count.index)}"
  content = element(data.template_file.constraints.*.rendered, count.index)
  bucket  = var.forseti_server_storage_bucket

  lifecycle {
    ignore_changes = [
      content,
      detect_md5hash,
    ]
  }
}
