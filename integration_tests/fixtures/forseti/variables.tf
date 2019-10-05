/**
*   Copyright 2018 Google LLC
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

variable "project_id" {
  description = "The ID of an existing Google project where Forseti will be installed"
}

variable "org_id" {
  description = "GCP Organization ID that Forseti will have purview over"
}

variable "billing_account" {
  description = "GCP Organization billing account details"
}

variable "domain" {
  description = "GCP Organization domain details that will be used for integration tests"
}

