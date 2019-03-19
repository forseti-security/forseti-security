data "template_file" "elasticsearch-startup-script" {
  template = "${file("${path.module}/scripts/install-elasticsearch.sh")}"

  vars {
    cluster_name  = "${var.elasticsearch_cluster_name}"
    project       = "${var.gcp_project}"
    zone          = "${var.gcp_zone}"
  }

}

resource "google_compute_instance" "elasticsearch" {
  count        = "${var.elasticsearch_node_count}"
  name         = "elasticsearch-node-${count.index}"
  machine_type = "${var.elasticsearch_machine_type}"
  zone         = "${var.gcp_zone}"

  # Allow to stop/start the machine to enable change machine type.
  allow_stopping_for_update = true

  # Use default Ubuntu image as operating system.
  boot_disk {
    initialize_params {
      image = "${var.gcp_ubuntu_1804_image}"
      size  = "${var.elasticsearch_disk_size_gb}"
    }
  }

  # Assign a generated public IP address. Needed for SSH access.
  network_interface {
    network       = "default"
    access_config = {}
  }

  # Tag for service enumeration.
  tags = ["elasticsearch"]

  # Enable the GCE discovery module to call required APIs.
  service_account {
    scopes = ["compute-ro"]
  }

  # Provision the machine with a script.
  metadata_startup_script = "${data.template_file.elasticsearch-startup-script.rendered}"
}
