data "template_file" "timesketch-server-startup-script" {
  template = "${file("${path.module}/scripts/install-timesketch.sh")}"
  vars {
    timesketch_admin_username = "${var.timesketch_admin_username}"
    timesketch_admin_password = "${random_string.timesketch-admin-password.result}"
    elasticsearch_node        = "${google_compute_instance.elasticsearch.*.name[0]}"
    postgresql_host           = "${google_sql_database_instance.timesketch-db-instance.ip_address.0.ip_address}"
    postgresql_db_name        = "${google_sql_database.timesketch-db.name}"
    postgresql_user           = "${google_sql_user.timesketch-db-user.name}"
    postgresql_password       = "${random_string.timesketch-db-password.result}"
    redis_host                = "${google_redis_instance.redis.host}"
    redis_port                = "${google_redis_instance.redis.port}"
  }
}

resource "random_string" "timesketch-admin-password" {
  length = 16
  special = false
}

resource "google_compute_address" "timesketch-server-address" {
  name = "timesketch-server-address"
}

resource "google_compute_instance" "timesketch-server" {
  name          = "timesketch-server"
  machine_type  = "${var.timesketch_machine_type}"
  zone          = "${var.gcp_zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.gcp_ubuntu_1804_image}"
      size  = "${var.timesketch_disk_size_gb}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"

    access_config {
      nat_ip = "${google_compute_address.timesketch-server-address.address}"
    }
  }

  # Allow HTTPS traffic
  tags = ["https-server"]

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.timesketch-server-startup-script.rendered}"
}

output "Server URL" {
  value = "https://${google_compute_address.timesketch-server-address.address}/"
}

output "Admin username" {
  value = "${var.timesketch_admin_username}"
}

output "Admin password" {
  value = "${random_string.timesketch-admin-password.result}"
}
