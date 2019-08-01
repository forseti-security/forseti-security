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

terraform {
  # Use local state storage by default. For production environments please
  # consider  using a more robust backend.
  backend "local" {
    path = "terraform.tfstate"
  }

  # Use Google Cloud Storage for robust, collaborative state storage.
  # Note: The bucket name need to be globally unique.
  #backend "gcs" {
  #  bucket = "GLOBALLY UNIQ BUCKET NAME"
  #}
}

provider "google" {
  project  = "${var.gcp_project}"
  region   = "${var.gcp_region}"
}

#------------#
# Timesketch #
#------------#
module "timesketch" {
  source                      = "./modules/timesketch"
  gcp_project                 = "${var.gcp_project}"
  gcp_region                  = "${var.gcp_region}"
  gcp_zone                    = "${var.gcp_zone}"
  gcp_ubuntu_1804_image       = "${var.gcp_ubuntu_1804_image}"
}

#------------#
# Turbinia   #
#------------#
module "turbinia" {
  source                      = "./modules/turbinia"
  gcp_project                 = "${var.gcp_project}"
  gcp_region                  = "${var.gcp_region}"
  gcp_zone                    = "${var.gcp_zone}"
  gcp_ubuntu_1804_image       = "${var.gcp_ubuntu_1804_image}"
}
