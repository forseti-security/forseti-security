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

output "Timesketch server URL" {
  description = "Timesketch server URL"
  value = "${module.timesketch.timesketch-server-url}"
}

output "Timesketch admin username" {
  description = "Timesketch admin username"
  value = "${module.timesketch.timesketch-admin-username}"
}

output "Timesketch admin password" {
  description = "Timesketch admin password"
  value = "${module.timesketch.timesketch-admin-password}"
}