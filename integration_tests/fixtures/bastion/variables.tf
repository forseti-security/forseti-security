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

variable "bastion_firewall_netblocks" {
  description = "The trusted Travis CI firewall network blocks for bastion host ssh access. https://docs.travis-ci.com/user/ip-addresses/"
  type        = string
  default     = "34.66.25.221/32 34.66.50.208/32 34.66.178.120/32 34.66.200.49/32 34.68.144.114/32 35.184.226.236/32 35.188.1.99/32 35.188.15.155/32 35.188.73.34/32 35.192.10.37/32 35.192.85.2/32 35.192.91.101/32 35.192.136.167/32 35.192.187.174/32 35.193.7.13/32 35.193.14.140/32 35.202.145.110/32 35.202.245.105/32 35.222.7.205/32 35.224.112.202/32 104.154.113.151/32 104.154.120.187/32 104.197.122.201/32 104.198.131.58/32"
}
   
variable "subnetwork" {
  description = "The name of the subnetwork in which the bastion host will be deployed."
  type        = "string"
}

variable "zone" {
  description = "The name of the zone in which the bastion host will be deployed."
  type        = "string"
}

