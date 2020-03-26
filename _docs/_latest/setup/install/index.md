---
title: Install Forseti on Google Compute Engine
order: 100
---

# {{ page.title }}

This guide explains how to install Forseti Security on Google Compute Engine.

---


## **Before you begin**

Before you set up Forseti Security, you will need:

* A Google Cloud Platform (GCP) organization you want to deploy
  Forseti for.
* An Organization Administrator Cloud Identity and Access Management (Cloud IAM)
  role so the script can assign the Forseti service account roles on the
organization Cloud IAM policy.
* A GCP project dedicated to Forseti. You can reuse the same project that has
  Forseti 1.0 installed in it.
* Enable billing on the project.

## **Google Cloud Shell Walkthrough**
A Google Cloud Shell walkthrough has been setup to make it easy for users who are new to Forseti and Terraform. 
This walkthrough provides a set of instructions to get a default installation of Forseti setup that can be used in a 
production environment.

If you are familiar with Terraform and would like to run Terraform from a different machine, you can skip this 
walkthrough and move onto the How to Deploy section below.


[![Open in Google Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fforseti-security%2Fterraform-google-forseti.git&cloudshell_git_branch=modulerelease520&cloudshell_working_dir=examples/install_simple&cloudshell_image=gcr.io%2Fgraphite-cloud-shell-images%2Fterraform%3Alatest&cloudshell_tutorial=.%2Ftutorial.md)


## **How to Deploy**

### **Install Terraform**
Terraform version 0.12 is required for this module, which can be downloaded from the 
[Terraform website](https://www.terraform.io/downloads.html).

In order to run this module you will need to be authenticated as a user that has access to the project and can 
create/authorize service accounts at both the organization and project levels. To login to GCP from a shell:

```bash
gcloud auth login
```

### **Service Account**

In order to execute this module you must have a Service Account with the 
[documented]({% link _docs/latest/setup/install/roles-and-permissions.md %}) IAM roles assigned and APIs enabled on the Forseti project.

The setup script (as discussed below) will create the Service Account, grant the roles and enable the 
APIs for you.

#### **Create the Service Account and enable required APIs**

{% include docs/latest/setup-script-credentials.md %}

{% include docs/latest/setup-script-credentials-gce.md %}

### **Terraform Configuration**
Example configurations are included in the 
[examples](https://github.com/forseti-security/terraform-google-forseti/tree/master/examples) directory on the Forseti 
Terraform Github repository.
You can copy these examples or use the snippet below as a starting point to your own custom configuration.

Create a file named `main.tf` in an empty directory and copy the contents below into the file.

```hcl
module "forseti" {
  source  = "terraform-google-modules/forseti/google"
  version = "~> 5.2.0"

  gsuite_admin_email       = "superadmin@yourdomain.com"
  domain                   = "yourdomain.com"
  project_id               = "my-forseti-project"
  org_id                   = "2313934234"
  
  config_validator_enabled = "true"
}
```

Config Validator Scanner is enabled when `config_validator_enabled` is set to 
`"true"`.

Forseti provides many optional settings for users to customize for their environment and security requirements. 

The default Forseti Server VM [machine type](https://cloud.google.com/compute/docs/machine-types) and 
Cloud SQL [machine type](https://cloud.google.com/sql/pricing#2nd-gen-pricing) 
have been set to `n1-standard-8` and `db-n1-standard-4` to account for larger GCP environments. 
These can be changed by providing the `server_type` and `cloudsql_type` variables.

View the sample variables to help you identify and set any customized values 
[here]({% link _docs/latest/setup/install/inputs.md %})

View the exhaustive list of inputs [here](https://github.com/forseti-security/terraform-google-forseti#inputs) 
to see all of the available options and default values.

### **Run Terraform**

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

## **Cleanup**
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

Now that Forseti has been deployed, you can [configure it further]({% link _docs/latest/configure/index.md %}) by following these additional steps.

View the list of outputs [here](https://github.com/forseti-security/terraform-google-forseti#outputs) to
identify important resources that have been created by the Forseti installation.

## **What's next**

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
 