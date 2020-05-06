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

locals {
  files = [
    "rules/enabled_apis_rules.yaml",
    "rules/location_rules.yaml",
  ]
}

data "template_file" "main" {
  count = length(local.files)
  template = file(
    "${path.module}/templates/${element(local.files, count.index)}",
  )

  vars = {
    domain                         = var.domain
    forseti_server_service_account = var.forseti_server_service_account
    org_id                         = var.org_id
    project_id                     = var.project_id
  }
}

resource "google_storage_bucket_object" "main" {
  count   = length(local.files)
  name    = element(local.files, count.index)
  content = element(data.template_file.main.*.rendered, count.index)
  bucket  = var.forseti_server_storage_bucket

  lifecycle {
    ignore_changes = [
      content,
      detect_md5hash,
    ]
  }
}
