### Setting up gcloud

First, install and configure the gcloud command-line tool so you can run 
the setup commands:

  1. Download and install the [gcloud command-line tool](https://cloud.google.com/sdk/gcloud/).
  1. Make sure gcloud is configured by running `gcloud info` and check that the
  Account and Project displayed match your Forseti Security project. If it
  doesn't match, run the following commands to configure gcloud for your
  Forseti Security project:
      1. Run `gcloud auth login` and use your Google credentials to authenticate.
      1. Run `gcloud init` and select your Forseti Security project and Google
      account.

### Enabling APIs

Enable each of the required APIs by running the following command:

  ```bash
  $ gcloud beta service-management enable <API NAME>
  ```
  
  {% include docs/required_apis.md %}

### Creating service accounts

Next, you'll create service accounts with Cloud Identity and Access Management
(Cloud IAM) roles to allow Forseti to read GCP data and to manage Forseti
modules. It's best to create your Forseti service accounts under a new GCP
project. You'll still be able to use the service accounts in other projects and
easily control the number of users who have Editor or Owner roles.

_For a detailed explanation of how Forseti Security uses service accounts, refer to 
["Forseti Service Accounts"]({% link _docs/guides/forseti-service-accounts.md %})._

To create and grant roles to a service account for Forseti Inventory, 
Scanner, and Enforcer, follow the steps below.

  1. Go to your [Google Cloud Platform console](https://console.cloud.google.com/iam-admin/serviceaccounts)
  and create a new service account.
  1. Grant these required Cloud IAM roles to the service account by running the
  following:
  
      _Organization Cloud IAM roles_
      
      Your authed account MUST have the Organization Admin role in order to add roles to the organization Cloud IAM policy.
      Adding roles to the organization Cloud IAM policy will allow Forseti the widest access to read data from your GCP 
      environment (i.e. the organization and all sub-resources).
      
      If you wish to grant the roles on a lower level (e.g. folder or project level), use the appropriate gcloud 
      commands (e.g. `gcloud projects add-iam-policy-binding PROJECT_ID ...` or 
      `gcloud alpha resource-manager folders add-iam-policy-binding FOLDER_ID ...`) instead. This will restrict 
      access to that resource and its sub-resources.
      
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/browser
      ```
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/compute.networkViewer
      ```
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/iam.securityReviewer
      ```
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/appengine.appViewer
      ```
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/servicemanagement.quotaViewer
      ```
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/cloudsql.viewer
      ```
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/compute.securityAdmin
      ```
      
      _Project Cloud IAM roles_
      
      These are necessary for reading/writing Forseti data in Google Cloud Storage and Cloud SQL.
      
      ```bash
      $ gcloud projects add-iam-policy-binding FORSETI_PROJECT_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/storage.objectViewer
      ```
      ```bash
      $ gcloud rpojects add-iam-policy-binding FORSETI_PROJECT_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/storage.objectCreator
      ```
      ```bash
      $ gcloud projects add-iam-policy-binding FORSETI_PROJECT_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/cloudsql.client
      ```
