### Enabling APIs

First, install and configure the gcloud command-line tool so you can
enable required APIs:

  1. Download and install the [gcloud command-line tool](https://cloud.google.com/sdk/gcloud/).
  1. Make sure gcloud is configured by running `gcloud info` and check that the
  Account and Project displayed match your Forseti Security project. If it
  doesn't match, run the following commands to configure gcloud for your
  Forseti Security project:
      1. Run `gcloud auth login` and use your Google credentials to authenticate.
      1. Run `gcloud init` and select your Forseti Security project and Google
      account.
  1. Enable the required APIs by running `gcloud beta service-management enable <API NAME>`
  for each of the following:
  
  {% include docs/required_apis.md %}

### Creating service accounts

Next, you'll create service accounts with Cloud Identity and Access Management
(Cloud IAM) roles to allow Forseti to read GCP data and to manage Forseti
modules. It's best to create your Forseti service accounts under a new GCP
project. You'll be able to use the service accounts in other projects and
easily control the number of users who have Editor or Owner roles.

**For a detailed explanation of how Forseti Security uses service accounts,
including your options and best practices, see the
[Forseti Security Best Practices Guide]({% link _docs/guides/best-practices.md %}).**

To create and grant roles to a service account for Forseti Inventory, 
Scanner, and Enforcer, follow the steps below.

  1. Go to your [Google Cloud Platform console](https://console.cloud.google.com/iam-admin/serviceaccounts)
  and create a new service account.
  1. Grant the required Cloud IAM roles to the service account by running the
  following:
  
      **Organization level bindings**
      
      Your authed account MUST have the Organization Admin role in order to add roles to the organization IAM policy.
      If you do not create these IAM policy bindings at the organization level, Forseti will only
      be able to read the GCP data of the resource (and any sub-resources) where you added the binding.
      
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
      
      **Note that binding this role at any other level than the Organization (e.g. a certain folder or project)
      limits `forseti_enforcer` to that resource and its sub-resources, if applicable.**
      
      ```bash
      $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
      --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
      --role=roles/compute.securityAdmin
      ```
      
      **Project level bindings**
      
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
