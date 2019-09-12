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

variable "network" {
  description = "The name of the network in which the bastion host will be deployed."
  type        = "string"
}

variable "project_id" {
  description = "The ID of the project in which resources will be created."
  type        = "string"
}

variable "subnetwork" {
  description = "The name of the subnetwork in which the bastion host will be deployed."
  type        = "string"
}

variable "zone" {
  description = "The name of the zone in which the bastion host will be deployed."
  type        = "string"
}
