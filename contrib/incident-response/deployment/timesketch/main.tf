resource "random_id" "infrastructure-random-id" {
  byte_length = 8
}

terraform {
  # Use local state storafe by default. For production environments please
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
