---
title: Manually Deploy IAM Explain on GCP
order: 302
---
#  {{ page.title }}

This page describes how to manually deploy the IAM Explain on Google Cloud Platform.

IAM Explain is a client-server based application that helps administrators,
auditors, and users of Google Cloud to understand, test, develop and debug Cloud
Identity and Access Management (Cloud IAM) policies. It can enumerate access by
resource, member, role or permission, answer why a principal has access on a
certain resource, or offer possible strategies for how to grant access.
In the latest version, IAM Explain is functional complete without a Forseti
deployment (see below for steps).
When you deploy IAM Explain, it creates a GCE instance and a MySQL database.
In order to use IAM Explain, you can login to the GCE instance and use the command line
tool `forseti_iam`. See below for usage examples.

Because IAM Explain and its API are still in early development, third party
clients won't be supported until a first stable API version is released. Only command
line is currently supported.

## Before you begin

Before you set up and deploy IAM Explain, you need to perform the following steps:

  1. Create a new project in your organization so IAM Explain's data will be protected from other users in the organization. Note that individuals with access on an organization or folder level might still have access though.
  1. Enable the billing of the created project.
  1. Activate Google Cloud Shell, clone the master branch of [Forseti repo](https://github.com/GoogleCloudPlatform/forseti-security) and change to `forseti-security` folder.
  ```bash
  $ git clone -b master https://github.com/GoogleCloudPlatform/forseti-security.git
  $ cd forseti-security
  ```
  1. Enable the required APIs on Google Cloud console or by running `gcloud beta service-management enable <API NAME>` for each of the following:
      * _Admin SDK API_: `admin.googleapis.com`
      * _AppEngine Admin API_: `appengine.googleapis.com`
      * _Cloud Resource Manager API_: `cloudresourcemanager.googleapis.com`
      * _Cloud SQL Admin API_: `sqladmin.googleapis.com`
      * _Cloud SQL API_: `sql-component.googleapis.com`
      * _Compute Engine API_: `compute.googleapis.com`
      * _Deployment Manager API_: `deploymentmanager.googleapis.com`
      * _Identity and Access Management (IAM) API_: `iam.googleapis.com`
  1. Setup a service account with [group collection enabled]({% link _docs/howto/explain/explain-gsuite-setup.md %}#enable-domain-wide-delegation-in-g-suite)
  1. Create another service account with the following roles
    - Organization level:
      - 'roles/browser',
      - 'roles/compute.networkViewer',
      - 'roles/iam.securityReviewer',
      - 'roles/appengine.appViewer',
      - 'roles/servicemanagement.quotaViewer',
      - 'roles/cloudsql.viewer',
      - 'roles/compute.securityAdmin',
      - 'roles/storage.admin',
    - Project level:
      - 'roles/cloudsql.client'

  The organization level roles are needed to create an inventory of your infrastructure. The sql client role is required to connect to the database which is created during the deployment.

## Customizing the deployment template

You can use the provided sample IAM Explain deployment file, `/forseti-security/deployment-templates/deploy-explain.yaml.sample` to customize your deployment.

  ```bash
  $ cp ./deployment-templates/deploy-explain.yaml.sample deploy-explain.yaml
  $ vim deploy-explain.yaml
  ```

The following values are mandatory to configure

  - `GSUITE_ADMINISTRATOR`: The email address of one of your Gsuite administrators. IAM Explain will assume the administrator's identity using OAuth2 temporarily while creating the inventory when figuring out what groups and users are in your Gsuite domain. Since you restricted the service account scope to user/group readonly, the service account cannot perform any other actions on your Gsuite domain than reading user & group data. This data is important to figure out effective IAM access when groups are assigned in IAM policies.

  - `ORGANIZATION_ID`: This is the id of your GCP organization.

  - `YOUR_SERVICE_ACCOUNT`: This is the service account holding the securityReviewer role from above. This is NOT the service account you set up for Gsuite domain wide delegation. If you choose to use a single service account for both purposes, put in that service account's ID.


After you configure the deployment template variables, run the following
command to create a new deployment:

  ```bash
  $ gcloud deployment-manager deployments create iam-explain \
  --config deploy-explain.yaml
  ```

## Provisioning the Gsuite service account

As of today, the IAM Explain requires access to the Gsuite domain wide delegation enabled service account file. If you downloaded the json key file, you can upload it with:

  ```bash
  $ gcloud compute scp groups.json ubuntu@host:/home/ubuntu/gsuite.json
  ```

Note that you have to substitute `groups.json` with the proper local json key filename.

## Using IAM Explain

You should now be able to login to your IAM Explain instance and use the `forseti_iam` command. You can skip the next section unless you are interested in a local deployment or want to gain an understanding of how IAM Explain's deployment works internally.

## Running the server (manually)

The IAM Explain server uses its own database for IAM models and simulations,
but queries the Forseti database for new imports. To run the IAM Explain server
together with a Forseti deployment, use one of the following methods:

  - Standard start/restart, if you used the deployment manager to create IAM
  Explain:

      ```bash
      $ systemctl start cloudsqlproxy
      $ systemctl start forseti
      ```

    - The services should automatically start right after the deployment.
    - You can find a deployment log at `/tmp/deployment.log`.

  - Start the server in a local installation:

      ```bash
      $ forseti_api '[::]:50051' 'mysql://root@127.0.0.1:3306/forseti_security' 'mysql://root@127.0.0.1:3306/explain_security' '/Users/user/deployments/forseti/groups.json' 'admin@gsuite.domain.com' '$organization_id' playground explain inventory
      ```

  - Use the SQL proxy to establish a connection to the Cloud SQL instance:
  
      ```bash
      $ cloud_sql_proxy -instances=$PROJECT:$REGION:$INSTANCE=tcp:3306
      ```

## Running the client

The IAM Explain client uses hierarchical command parsing. At the top level,
commands divide into "explainer" and "playground".

### Getting started

The first thing you need to do with a fresh instance is to create an inventory:

```bash
$ forseti_iam inventory create
```

This will crawl the organization and create an inventory in a single table for long term storage.

In order to the other services like playground and explain, you need to create a so called model. A model is a data model instance created from an inventory. You can have multiple models at the same time from the same or different inventories. Models are what you work on, inventory is just the long term storage format. In order to create a model, the first question is which inventory you want to create it from. Use the inventory list to see what inventories are available or create a new one using the above command.

```bash
$ forseti_iam inventory list
```

In order to create a model from an inventory, use the inventory id. You can choose an arbitrary name to associate your work with the model:
```bash
$ forseti_iam explainer create_model --id ID inventory NAME
```

In order to use a newly created or existing model, use the list functionality and either set the handle of the model in the command line or using an environment variable:

```bash
$ forseti_iam explainer list_models
$ export IAM_MODEL=....
$ forseti_iam explainer list_permissions
```

Or:

```bash
$ forseti_iam explainer list_models
$ forseti_iam --use_model ... explainer list_permissions
```

From here, we recommend you extensively use the `--help` parameter in all variations to explore the functionality of each service. Playground is the simulator which allows you to change a model, Explainer is the tool that allows you to ask questions stated in the introduction like 'who has access to what and why'.

  