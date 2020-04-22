---
title: Run The Test Suite Locally
order: 045
---

# {{ page.title }}

This page describes how to run the integration test suite for your Forseti
contributions on your local dev environment. 

## **Setting up development environment**

- Create a new project in your organization.
- Terraform uses an IAM Service Account to deploy and configure resources on 
behalf of the user. You can create the Service account, and grant the necessary 
roles to the Service Account manually or by running the helper script. 

### **Creating Service Account by running the helper script**

In order to execute this script, you must have an account with the
`Billing Account Administrator` role should be granted to the admin account. This
is required to create the Service Account using the helper script. You can revoke 
this role after the service account is created.
- To run the [helper script](https://github.com/terraform-google-modules/terraform-google-project-factory/blob/master/helpers/setup-sa.sh), 
clone the [Terraform Google Project factory repository](https://github.com/terraform-google-modules/terraform-google-project-factory)
and run the following command:

`./helpers/setup-sa.sh <ORGANIZATION_ID> <PROJECT_NAME> <BILLING_ACCOUNT>`

### **Creating Service Account and granting roles manually**

Alternatively, you can grant the following roles and enable the APIs manually.

On the organization:

* roles/billing.user
* roles/iam.securityReviewer
* roles/resourcemanager.folderViewer
* roles/resourcemanager.organizationAdmin
* roles/resourcemanager.organizationViewer
* roles/resourcemanager.projectCreator

On the project:

* roles/cloudkms.admin
* roles/cloudsql.admin
* roles/compute.instanceAdmin
* roles/compute.networkViewer
* roles/compute.securityAdmin
* roles/iam.serviceAccountAdmin
* roles/iam.serviceAccountUser
* roles/owner
* roles/serviceusage.serviceUsageAdmin
* roles/storage.admin


Enable the following APIs on the Forseti project:

* cloudkms.googleapis.com
* cloudresourcemanager.googleapis.com
* compute.googleapis.com
* serviceusage.googleapis.com

### **Setting up environment variables**

Set the following environment variables from the bash shell:

```
export SERVICE_ACCOUNT_JSON=<JSON_KEY_OF_THE_NEWLY_CREATED_SERVICE_ACCOUNT> \

export TF_VAR_billing_account=<YOUR_BILLING_ACCOUNT> \

export TF_VAR_domain=<YOUR_DOMAIN> \

export TF_VAR_forseti_email_recipient=<EMAIL_RECIPIENT> \

export TF_VAR_forseti_email_sender=<EMAIL_SENDER> \ 

export TF_VAR_forseti_version=<BRANCH_NAME> \ 

export TF_VAR_gsuite_admin_email=<GSUITE_EMAIL_ADDRESS> \

export TF_VAR_inventory_performance_cai_dump_paths=<PATH_TO_CAI_DUMP> \

export TF_VAR_kms_key=<KMS_KEY> \

export TF_VAR_kms_keyring=<KMS_KEYRING> \ 

export TF_VAR_org_id=<YOUR_ORGANIZATION_ID> \

export TF_VAR_project_id=<YOUR_PROJECT_ID> \

export TF_VAR_sendgrid_api_key=<SENDGRID_API_KEY>

```

## **Running the test suite**

Run the following command after setting up environment variables:

```
docker container run -it -e KITCHEN_TEST_BASE_PATH="integration_tests/tests" -e 
SERVICE_ACCOUNT_JSON -e TF_VAR_project_id -e TF_VAR_org_id -e 
TF_VAR_billing_account -e TF_VAR_domain -e TF_VAR_forseti_email_recipient -e
TF_VAR_forseti_email_sender -e TF_VAR_forseti_version -e 
TF_VAR_gsuite_admin_email -e TF_VAR_inventory_performance_cai_dump_paths -e
TF_VAR_kms_key -e TF_VAR_kms_keyring -e TF_VAR_sendgrid_api_key
-v $(pwd):/workspace gcr.io/cloud-foundation-cicd/cft/developer-tools:0.4.1
/bin/bash
```

- Run `kitchen create --test-base-path="integration_tests/tests"`. This is 
similar to `terraform init`, and should be run once in the beginning, and 
whenever there are configuration/provider changes.

- Run `kitchen converge --test-base-path="integration_tests/tests"` to setup the 
test environment, deploy Forseti and create the resources in the test 
environment.

- Run `kitchen verify --test-base-path="integration_tests/tests"` to run the 
InSpec tests.

- Run `kitchen destroy --test-base-path="integration_tests/tests"` to destroy 
the test environment.
