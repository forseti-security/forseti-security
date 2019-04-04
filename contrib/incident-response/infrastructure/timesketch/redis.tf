# Copyright 2019 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Enable Google Cloud Resource Manager API for the project.
resource "google_project_service" "cloud-resource-service-api" {
  project   = "${var.gcp_project}"
  service   = "cloudresourcemanager.googleapis.com"
}

# Enable Google Cloud Memorystore for Redis API for the project.
resource "google_project_service" "redis-service-api" {
  project     = "${var.gcp_project}"
  service     = "redis.googleapis.com"
  depends_on  = ["google_project_service.cloud-resource-service-api"]
}

# Redis is used as the task queue backend for importing data into Timesketch.
resource "google_redis_instance" "redis" {
  name           = "redis"
  memory_size_gb = 1
  depends_on     = ["google_project_service.redis-service-api"]
}
