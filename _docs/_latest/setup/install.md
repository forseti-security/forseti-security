---
title: Install
order: 001
---

# {{ page.title }}

This guide explains how to install Forseti Security.

---

## Before you begin

Before you set up Forseti Security, you will need:

* A Google Cloud Platform (GCP) organization you want to deploy
  Forseti for.
* An Organization Administrator Cloud Identity and Access Management (Cloud IAM)
  role so the script can assign the Forseti service account roles on the
organization Cloud IAM policy.
* A GCP project dedicated to Forseti. You can reuse the same project that has
  Forseti 1.0 installed in it.
* Enable billing on the project.

## Setting up Forseti Security

The Forseti Terraform module is the only supported method of installing Forseti Security The default infrastructure for 
Forseti is Google Compute Engine. This module also supports installing Forseti on Google Kubernetes Engine (GKE), 
and at some point in the future will become the default. For more information on installing Forseti on-GKE, please see 
the [detailed guide on setting up Forseti on-GKE]({% link _docs/latest/setup/forseti-on-gke.md %}).

## Google Cloud Shell Walkthrough
A Google Cloud Shell walkthrough has been setup to make it easy for users who are new to Forseti and Terraform. 
This walkthrough provides a set of instructions to get a default installation of Forseti setup that can be used in a 
production environment.

If you are familiar with Terraform and would like to run Terraform from a different machine, you can skip this 
walkthrough and move onto the How to Deploy section below.

[![Open in Google Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fforseti-security%2Fterraform-google-forseti.git&cloudshell_git_branch=module-release-5.0.0&cloudshell_working_dir=examples/install_simple&cloudshell_image=gcr.io%2Fgraphite-cloud-shell-images%2Fterraform%3Alatest&cloudshell_tutorial=.%2Ftutorial.md)

## How to Deploy
In order to run this module you will need to be authenticated as a user that has access to the project and can 
create/authorize service accounts at both the organization and project levels. To login to GCP from a shell:

```bash
gcloud auth login
```

### Install Terraform
Terraform version 0.12 is required for this module, which can be downloaded from the 
[Terraform website](https://www.terraform.io/downloads.html).

### Create the Service Account and enable required APIs

#### Service Account
The Service Account and required APIs can be setup automatically with a provided script on the 
[Forseti Terraform Github repository](https://github.com/forseti-security/terraform-google-forseti/blob/master/helpers/setup.sh). 
This can also be done manually by reviewing the [Requirements](#requirements) section.

```bash
git clone https://github.com/forseti-security/terraform-google-forseti.git
```

```bash
cd terraform-google-forseti
```

```bash
./helpers/setup.sh -p PROJECT_ID -o ORG_ID
```

This will create a service account called `cloud-foundation-forseti-<suffix>`,
assign it the proper roles, and download the service account credentials to
`${PWD}/credentials.json`.

If you are using the Real-Time Enforcer, you will need to generate a
service account with a few extra roles. This can be enabled with the `-e`
flag:

```bash
./helpers/setup.sh -p PROJECT_ID -o ORG_ID -e
```

Utilizing a shared VPC via a host project is supported with the `-f` flag:

```bash
./helpers/setup.sh -p PROJECT_ID -f HOST_PROJECT_ID -o ORG_ID
```

#### APIs
For this module to work, you need the following APIs enabled on the Forseti project:

{% include docs/latest/forseti-terraform-setup-apis.md %}

### Terraform Configuration
Example configurations are included in the 
[examples](https://github.com/forseti-security/terraform-google-forseti/tree/master/examples) directory on the Forseti 
Terraform Github repository.
You can copy these examples or use the snippet below as a starting point to your own custom configuration.

Create a file named `main.tf` in an empty directory and copy the contents below into the file.

```hcl

provider "google" {
  credentials = "${file("/path/to/credentials.json")}"
}

module "forseti" {
  source  = "terraform-google-modules/forseti/google"
  version = "~> 5.0.0"

  gsuite_admin_email = "superadmin@yourdomain.com"
  domain             = "yourdomain.com"
  project_id         = "my-forseti-project"
  org_id             = "2313934234"
}
```

Forseti provides many optional settings for users to customize for their environment and security requirements. 

The default Forseti Server VM [machine type](https://cloud.google.com/compute/docs/machine-types) and 
Cloud SQL [machine type](https://cloud.google.com/sql/pricing#2nd-gen-pricing) 
have been set to `n1-standard-8` and `db-n1-standard-4` to account for larger GCP environments. 
These can be changed by providing the `server_type` and `cloudsql_type` variables.

View the list of [inputs](#inputs) to see all of the available options.

### Run Terraform
Forseti is ready to be installed! First you will need to initialize Terraform to download any of the module 
dependencies.

```bash
terraform init
```

The configuration can now be applied which will determine the necessary actions to perform on the GCP project.

```bash
terraform apply
```

Review the Terraform plan and enter `yes` to perform these actions.

### Cleanup
Remember to cleanup the service account used to install Forseti either manually or by running the command:

```bash
./scripts/cleanup.sh -p PROJECT_ID -o ORG_ID -s cloud-foundation-forseti-<suffix>
```

This will deprovision and delete the service account, and then delete the credentials file.

If the service account was provisioned with the roles needed for the real time
policy enforcer, you can set the `-e` flag to clean up those roles as well:

```bash
./scripts/cleanup.sh -p PROJECT_ID -o ORG_ID -S cloud-foundation-forseti-<suffix> -e
```

## Forseti Configuration
Now that Forseti has been deployed, there are additional steps that you can follow to further 
[configure Forseti]({% link _docs/latest/configure/index.md %}). Some of the commonly used features are 
listed below:

- [Enable G Suite Scanning]({% link _docs/latest/configure/inventory/gsuite.md %})
- [Enable Cloud Security Command Center Notifications]({% link _docs/latest/configure/notifier/index.md %}#cloud-scc-notification)
  - After activating this integration, add the Source ID into the Terraform configuration using 
  the `cscc_source_id` input and re-run the Terraform `apply` command.

## Requirements
This section describes in detail the requirements necessary to deploy Forseti. The setup helper script automates the 
service account creation and enabling the APIs for you. Read through this section if you are not using the setup script 
or want to understand these details.

1. Install Terraform.
2. A GCP project to deploy Forseti into. The 
[Google Project Factory Terraform](https://github.com/terraform-google-modules/terraform-google-project-factory) module 
can be used to provision the project with the required APIs enabled, along with a Shared VPC connection.
3. The Service Account used to execute this module has the right permissions.
4. Enable the required GCP APIs to allow the Terraform module to deploy Forseti.

## Software Dependencies

### Terraform and Plugins
- [Terraform](https://www.terraform.io/downloads.html) 0.12
- [Terraform Provider for GCP](https://github.com/terraform-providers/terraform-provider-google) 2.11.0
- [Terraform Provider Templates](https://www.terraform.io/docs/providers/template/index.html) 2.0

## Service Account
In order to execute this module you must have a Service Account with the following IAM roles assigned.

### IAM Roles
For this module to work, you need the following roles enabled on the Service Account.

{% include docs/latest/forseti-terraform-sa-roles.md %}

## Inputs
Forseti provides many optional settings for users to customize for their environment and security requirements. 
View the list of inputs below to see all of the available options.

{% include docs/latest/forseti-terraform-inputs.md %}

## Outputs
When completed, the Terraform deployment will output a list of values on the terminal that can help users identify 
important resources that have been created by the Forseti installation:

{% include docs/latest/forseti-terraform-outputs.md %}

## What's next

* Learn how to customize
  [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
  [Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Configure Forseti Notifier to send
  [email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications).
* Enable
  [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
  for processing by Forseti.
* Learn how to [configure Forseti to run from non-organization
  root]({% link _docs/latest/configure/general/non-org-root.md %}).
  
