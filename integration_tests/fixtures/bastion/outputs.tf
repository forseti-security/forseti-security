/**
 * Copyright 2018 Google LLC
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

output "host" {
  description = "The external IP address of the bastion host."
  value       = "${google_compute_instance.main.network_interface.0.access_config.0.nat_ip}"
}

output "port" {
  description = "The port to use when connecting to the bastion host."
  value       = "22"
}

output "private_key" {
  description = "The contents of an SSH key file to use when connecting to the bastion host."
  value       = "${tls_private_key.main.private_key_pem}"
}

output "user" {
  description = "The user to use when connecting to the bastion host."
  value       = "${local.user}"
}
