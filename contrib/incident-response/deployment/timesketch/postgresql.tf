resource "random_string" "timesketch-db-password" {
  length = 16
  special = false
}

resource "google_sql_user" "timesketch-db-user" {
  name     = "timesketch"
  instance = "${google_sql_database_instance.timesketch-db-instance.name}"
  password = "${random_string.timesketch-db-password.result}"
}

resource "google_sql_database" "timesketch-db" {
  name     = "timesketch-db"
  instance = "${google_sql_database_instance.timesketch-db-instance.name}"
}

resource "google_sql_database_instance" "timesketch-db-instance" {
  name              = "timesketch-db-instance-${random_id.infrastructure-random-id.hex}"
  region            = "${var.gcp_region}"
  database_version  = "POSTGRES_9_6"

  settings {
    tier = "db-f1-micro"

    ip_configuration {
      ipv4_enabled = true
      authorized_networks = {
        name  = "timesketch-server"
        value = "${google_compute_address.timesketch-server-address.address}"
      }
    }

    location_preference {
      zone = "${var.gcp_region}-b"
    }
  }
}
