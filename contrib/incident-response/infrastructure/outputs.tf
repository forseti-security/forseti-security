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

# Timesketch outputs
output "timesketch-server-url" {
  value = "${module.timesketch.timesketch-server-url}"
}

output "timesketch-admin-username" {
  value = "${module.timesketch.timesketch-admin-username}"
}

output "timesketch-admin-password" {
  value = "${module.timesketch.timesketch-admin-password}"
}

# Turbinia outputs
output "turbinia-config" {
  value = "${module.turbinia.turbinia-config}"
}