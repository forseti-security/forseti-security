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

resource "google_project_iam_custom_role" "forseti-enforcer-admin" {
  role_id     = "forsetiEnforcerAdmin"
  title       = "Forseti Enforcer Admin"
  description = "Access to delete firewall rules and update policy."
  permissions = [
    "compute.firewalls.create",
    "compute.firewalls.delete",
    "compute.networks.updatePolicy",
  ]
  project     = var.project_id
}

resource "google_project_iam_member" "forseti-server-enforcer-admin-role" {
  role    = google_project_iam_custom_role.forseti-enforcer-admin.id
  project = var.project_id
  member  = "serviceAccount:${var.forseti_server_service_account}"
}

