### Enabling APIs

First, you'll install and configure the gcloud command-line tool so you can
enable required APIs:

  1. Download and install the [gcloud command-line tool](https://cloud.google.com/sdk/gcloud/).
  1. Make sure gcloud is configured by running `gcloud info` and check that the
  Account and Project displayed match your Forseti Security project. If it
  doesn't match, run the following commands to configure gcloud for your
  Forseti Security project:
  
     * Run `gcloud auth login` and use your Google credentials to authenticate.
     * Run `gcloud init` and select your Forseti Security project and Google
        account.
  1. Enable the required APIs by running `gcloud beta service-management enable`
  for each of the following API paths:
      - **Cloud SQL API:** `sql-component.googleapis.com`
      - **Cloud SQL Admin API:** `sqladmin.googleapis.com`
      - **Cloud Resource Manager API:** `cloudresourcemanager.googleapis.com`
      - **Admin SDK API:** `admin.googleapis.com`
      - **Deployment Manager API:** `deploymentmanager.googleapis.com`

### Creating service accounts

Next, you'll create service accounts with Cloud Identity and Access Management
(Cloud IAM) roles to allow Forseti to read GCP data and to manage Forseti
modules. It's best to create your Forseti service accounts under a new GCP
project. You'll be able to use the service accounts in other projects and
easily control the number of users who have Editor or Owner roles.

To create a service account for Forseti Inventory, Scanner, and Enforcer, follow the steps below:

  1. Go to your [Google Cloud Platform console](https://console.cloud.google.com/iam-admin/serviceaccounts)
  and create a new service account.
  1. Create and download the json key to your local environment.
  1. Set an environment variable to configure the Application Default
  Credentials to reference the key by running
  
          export GOOGLE_APPLICATION_CREDENTIALS=SERVICE_ACCOUNT_KEY_PATH
          
  where `SERVICE_ACCOUNT_KEY_PATH` is the path to the json service account key you just downloaded.
  1. Grant the required Cloud IAM roles to the service account by running the
  following:

      ```
      gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/browser
      ```
      ```
      gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/compute.networkAdmin
      ```
      ```
      gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/editor
      ```
      ```
      gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/iam.securityReviewer
      ```
      ```
      gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/resourcemanager.folderAdmin
      ```
      ```
      gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/storage.admin
      ```
