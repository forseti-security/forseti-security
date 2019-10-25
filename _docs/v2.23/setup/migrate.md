---
title: Migrate from Python Installer to Terraform Module
order: 007
---

# {{ page.title }}

This guide explains how to migrate a Forseti deployment from the
deprecated Python Installer to the new Terraform module.

If you have any
questions about this process, please contact us by
[email](mailto:discuss@forsetisecurity.org) or on
[Slack](https://forsetisecurity.slack.com/join/shared_invite/enQtNDIyMzg4Nzg1NjcxLTM1NTUzZmM2ODVmNzE5MWEwYzAwNjUxMjVkZjhmYWZiOGZjMjY3ZjllNDlkYjk1OGU4MTVhZGM4NzgyZjZhNTE).

---

## Prerequisites

Before you begin the migration process, you will need:

- A Forseti deployment of at least v2.18.0; follow the
  [upgrade guide]({% link _docs/v2.23/setup/upgrade.md %}) as
  necessary.
- A version of the
  [Terraform command-line interface](https://www.terraform.io/downloads.html)
  in the 0.12 series.
- The domain and ID of the Google Cloud Platform (GCP) organization in
  which Forseti is deployed.
- The ID of the GCP project in which Forseti is deployed.
- The suffix appended to the names of the Forseti resources; this is
  likely a string of seven characters like a1b2c3d.
- A service account in the organization with the
  [roles required by the Terraform module](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/4.3.0#iam-roles).
- A
  [JSON key file](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#creating_service_account_keys)
  for the service account.

If you deployed Forseti in a shared VPC then you will also need:

- The ID of the GCP project in which the shared VPC is hosted.
- The ID of the shared VPC network in which Forseti is deployed.
- The ID of the subnetwork from the shared VPC network in which Forseti is deployed.

## Configuring Terraform

Terraform can assume the identity of a service account through a
strategy called
[Application Default Credentials](https://cloud.google.com/docs/authentication/production#providing_credentials_to_your_application)
when provisioning resources. To enable this approach, set the
appropriate environment variable to the path of the service account JSON
key file:

```sh
export GOOGLE_APPLICATION_CREDENTIALS="PATH_TO_JSON_KEY_FILE"
```

In the working directory, create a file named `main.tf` with content
like the following, replacing values based on the comments:

```hcl
terraform {
  required_version = ">= 0.12.0"
}

provider "google" {
  version = "~> 2.11.0"
}

provider "local" {
  version = "~> 1.3"
}

provider "null" {
  version = "~> 2.0"
}

provider "template" {
  version = "~> 2.0"
}

provider "random" {
  version = "~> 2.0"
}

module "forseti" {
  source = "terraform-google-modules/forseti/google"
  version = "~> 5.0"

  # Replace these argument values with those obtained in the Prerequisites section
  domain               = "DOMAIN"
  project_id           = "PROJECT_ID"
  resource_name_suffix = "RESOURCE_NAME_SUFFIX"
  org_id               = "ORG_ID"

  # Replace these argument values with those obtained in the Prerequisites section if a shared VPC is used
  # Remove these arguments if a shared VPC is not used
  network         = "SHARED_VPC_NETWORK_ID"
  network_project = "SHARED_VPC_PROJECT_ID"
  subnetwork      = "SHARED_VPC_SUBNETWORK_ID"

  client_instance_metadata = {
    enable-oslogin = "TRUE"
  }
  enable_write         = true
  manage_rules_enabled = false
}
```

Note that this configuration assumes that the default path of the
Python Installer instructions was followed. You should review the
[Terraform module inputs](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/4.2.0?tab=inputs)
to determine if any additional configuration is required.

Also note that while this minimal Terraform configuration will create
state locally, it is strongly recommended to
[use a Google Cloud Storage bucket](https://www.terraform.io/docs/backends/types/gcs.html)
to store state remotely. However, the setup of remote state is out of
scope for this article.

## Obtaining Import Helper

The Terraform module repository includes an import helper script which
will import the existing Forseti resources to a new Terraform state.
Download the script to the working directory and ensure it is executable.

```sh
curl --location --remote-name https://raw.githubusercontent.com/forseti-security/terraform-google-forseti/master/helpers/import.sh
chmod +x import.sh
./import.sh -h
```

## Importing Existing Resources

Initialize the Terraform state:

```sh
terraform init
```

Import the existing resources to the Terraform state, replacing the
uppercase values with the aforementioned values:

```sh
./import.sh -m MODULE_LOCAL_NAME -o ORG_ID -p PROJECT_ID -s RESOURCE_NAME_SUFFIX -z GCE_ZONE [-n NETWORK_PROJECT_ID]
```

Observe the expected Terraform changes
([discussed below](#terraform-changes)):

```sh
terraform plan
```

Apply the Terraform changes:

```sh
terraform apply
```

At this point, the existing Forseti deployment has been migrated to a
Terraform state.

## Terraform Changes

Because there is not an exact mapping between the deprecated Python
Installer and the Terraform module, some changes will occur when
Terraform assumes management of the Forseti deployment.

You should carefully review this section as well as the output from
`terraform plan` to ensure that all changes are expected and acceptable.

### Created

- The `forseti-server-gcp-RESOURCE_NAME_SUFFIX` service account will gain 
  the IAM Service Account Token Creator (`roles/iam.serviceAccountTokenCreator`) 
  role

### Updated In-Place

- The `forseti-client-deny-all-RESOURCE_NAME_SUFFIX` firewall rule and
  the `forseti-server-deny-all-RESOURCE_NAME_SUFFIX` firewall rule will
  both update from denying all protocols to denying ICMP, TCP, and UDP
- The `forseti-server-allow-grpc-RESOURCE_NAME_SUFFIX` firewall rule
  will update to only allow traffic from the
  `forseti-client-gcp-RESOURCE_NAME_SUFFIX` service account and to allow
  traffic to port 50052 in addition to 50051

### Destroyed and Replaced

- The `forseti-client-allow-ssh-external-RESOURCE_NAME_SUFFIX` firewall
  rule and the `forseti-server-allow-ssh-external-RESOURCE_NAME_SUFFIX`
  firewall rule will both be replaced due to a naming change, but the new firewall
  rules will be equivalent
- The `forseti-client-vm-RESOURCE_NAME_SUFFIX` compute instance and the
  `forseti-server-vm-RESOURCE_NAME_SUFFIX` compute instance will be
  replaced due to changes in metadata startup scripts, boot disk sizes
  and boot disk types; these VMs should be stateless but ensure that
  any customizations are captured before applying this change
- The `configs/forseti_conf_client.yaml` object in the
  `forseti-client-RESOURCE_NAME_SUFFIX` storage bucket and the
  `configs/forseti_conf_server.yaml` object in the
  `forseti-server-RESOURCE_NAME_SUFFIX` storage bucket will be replaced
  due to a lack of Terraform import support
