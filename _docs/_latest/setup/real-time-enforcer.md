---
title: Deploy Real-Time Enforcer on GCP
order: 005
---

# {{ page.title }}

{% include docs/latest/beta-release-feature.md %}

This guide explains how to setup Real-Time Enforcer using Terraform.

Get the latest version of the Forseti Terraform 
module [here](https://registry.terraform.io/modules/terraform-google-modules/forseti/google). 

## Setting up Real-Time Enforcer

In your `main.tf` file, include the following Real-Time Enforcer specific modules in the order provided:
1. `real_time_enforcer_roles` creates and assigns the custom roles required for Real-Time Enforcer to access and remediate resources.
1. `real_time_enforcer_organization_sink` creates and sets up an organization 
level [logging sink](https://cloud.google.com/logging/docs/api/tasks/exporting-logs) 
and a [Pub/Sub topic](https://cloud.google.com/pubsub/docs/overview) to publish to.
1. `real_time_enforcer` creates and sets up the necessary resources to run Real-Time Enforcer that are not covered by the first two modules, which include:
    * Real-Time Enforcer VM running [Container Optimized OS](https://cloud.google.com/container-optimized-os/docs/concepts/features-and-benefits)
    * Real-Time Enforcer Service account
    * GCS bucket with Real-Time Enforcer policy files
    * Pub/Sub subscription
    * Forseti specific firewall rules
    * Real-Time Enforcer application Docker image
    * Open Policy Agent server Docker image

```
module "forseti" {
  source                   = "terraform-google-modules/forseti/google"
  project_id               = "${var.project_id}"
  gsuite_admin_email       = "${var.gsuite_admin_email}"
  org_id                   = "${var.org_id}"
  domain                   = "${var.domain}"
  client_instance_metadata = "${var.instance_metadata}"
  server_instance_metadata = "${var.instance_metadata}"
}

module "real_time_enforcer_roles" {
   source = "terraform-google-modules/forseti/google/modules/real_time_enforcer_roles"
   org_id = "${var.org_id}"
   suffix = "${module.forseti.suffix}"
}

module "real_time_enforcer_organization_sink" {
  source            = "terraform-google-modules/forseti/google/modules/real_time_enforcer_organization_sink"
  pubsub_project_id = "${var.project_id}"
  org_id            = "${var.org_id}"
}

 module "real_time_enforcer" {
   source                     = "terraform-google-modules/forseti/google/modules/real_time_enforcer"
   project_id                 = "${var.project_id}"
   org_id                     = "${var.org_id}"
   enforcer_instance_metadata = "${var.instance_metadata}"
   topic                      = "${module.real_time_enforcer_organization_sink.topic}"
   enforcer_viewer_role       = "${module.real_time_enforcer_roles.forseti-rt-enforcer-viewer-role-id}"
   enforcer_writer_role       = "${module.real_time_enforcer_roles.forseti-rt-enforcer-writer-role-id}"
   suffix                     = "${module.forseti.suffix}"
}
```

## Run Terraform

1.  Run `terraform init` to get the modules and plugins.
    * If you have already installed Forseti using Terraform previously, you can skip step 3 and add the following 
    roles to your `cloud-foundation-forseti` service account:
        * **On the organization:**
            * `roles/iam.organizationRoleAdmin`
            * `roles/logging.configWriter`
        * **On the project:**
            * `roles/pubsub.admin`
1. Run `./helpers/setup.sh -p <project_id> -o <org_name> -e` to create a service account called 
`cloud-foundation-forseti`, give it the proper roles, and download it to your current directory. 
    * _Note:_ using this script assumes that you are currently authenticated as a user that can create/authorize 
    service accounts at both the organization and project levels. This script will also activate necessary APIs 
    required for Terraform to run.
1. Ensure that you have the following additional roles assigned to the newly created service account:
    * **On the organization:**
        * `roles/resourcemanager.organizationAdmin`
        * `roles/securityReviewer`
    * **On the project:**
        * `roles/owner`
    * **On the host project (when using shared VPC):**
        * `roles/compute.securityAdmin`
        * `roles/compute.networkAdmin`
1. Run `terraform plan` to see the infrastructure plan.
1. Run `terraform apply` to apply the infrastructure build.