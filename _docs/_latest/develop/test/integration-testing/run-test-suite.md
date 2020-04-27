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

- In order to execute this script, you must have an Organization Administrator 
Cloud Identity and Access Management (Cloud IAM) role so the script can assign
the Forseti services account roles on the organization Cloud IAM policy.
- Follow the instructions [here](https://forsetisecurity.org/docs/latest/setup/install/index.html#create-the-service-account-and-enable-required-apis)
to run the helper script that creates the Service Account and grants required 
roles to the Service Account.

### **Creating Service Account and granting roles manually**

Alternatively, you can create a Service Account yourself, and grant it the 
[documented](https://forsetisecurity.org/docs/latest/setup/install/roles-and-required-apis.html)
IAM roles and enable the APIs on the Forseti project.


### **Setting up environment variables**

- Running the email notification test and inventory performance tests involve 
some manual work to encrypt the credentials using KMS key and setting
environment variables to the mock data files. Please reach out to
the [Forseti Security Team](https://forsetisecurity.org/docs/latest/use/get-help.html) 
for guidance on running these tests.

**Note:** 
- To successfully run other tests, you need to comment out 
`inventory-performance` and `notifier-inventory-summary-email` controls from the 
[kitchen config file](https://github.com/forseti-security/forseti-security/blob/master/.kitchen.yml),
and set `TF_VAR_inventory_performance_cai_dump_paths`, `TF_VAR_kms_key` and 
`TF_VAR_kms_keyring` environment variables to `""`.
- `cloudkms.googleapis.com` API should be enabled to run inventory performance 
tests.

Set the following environment variables from the bash shell as suggested below 
to run the rest of the integration tests:

```
export SERVICE_ACCOUNT_JSON=<JSON_KEY_OF_THE_NEWLY_CREATED_SERVICE_ACCOUNT> \

export TF_VAR_billing_account=<YOUR_BILLING_ACCOUNT> \

export TF_VAR_domain=<YOUR_DOMAIN> \

export TF_VAR_forseti_version=<BRANCH_NAME> \ 

export TF_VAR_gsuite_admin_email=<GSUITE_EMAIL_ADDRESS> \

export TF_VAR_inventory_performance_cai_dump_paths="" \

export TF_VAR_kms_key="" \

export TF_VAR_kms_keyring="" \ 

export TF_VAR_org_id=<YOUR_ORGANIZATION_ID> \

export TF_VAR_project_id=<YOUR_PROJECT_ID>
```

## **Running the test suite**

Run the following command after setting up environment variables:

```
docker container run -it -e KITCHEN_TEST_BASE_PATH="integration_tests/tests" -e 
SERVICE_ACCOUNT_JSON -e TF_VAR_project_id -e TF_VAR_org_id -e 
TF_VAR_billing_account -e TF_VAR_domain -e TF_VAR_forseti_version -e 
TF_VAR_gsuite_admin_email -e TF_VAR_inventory_performance_cai_dump_paths -e
TF_VAR_kms_key -e TF_VAR_kms_keyring -v $(pwd):/workspace 
gcr.io/cloud-foundation-cicd/cft/developer-tools:0.4.1 /bin/bash
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
