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

### Creating service accounts

If you are setting up a developer environment, you can just use the Google credentials 
from when you ran `gcloud auth login` and go to the next section.

If you are running Forseti on GCP, you'll need create service accounts with 
Cloud Identity and Access Management (Cloud IAM) roles to allow Forseti to 
read GCP data and to manage Forseti modules.

_For a detailed explanation of how Forseti Security uses service accounts, refer to 
["Forseti Service Accounts"]({% link _docs/guides/forseti-service-accounts.md %})._

To create and grant roles to a service account for Forseti Inventory, 
Scanner, and Enforcer, follow the steps below.

  1. Go to your [Google Cloud Platform console](https://console.cloud.google.com/iam-admin/serviceaccounts)
  and create a new service account.
  1. Create and download a json key for the service account.
  1. Run the following command to assume the service account credentials:
  
  ```bash
  gcloud auth activate-service-account --key-file=PATH/TO/KEYFILE.json
  ```

To create a separate service account for enabling G Suite data collection, follow the steps in 
["Enabling GSuite Google Groups Collection"]({% link _docs/howto/configure/gsuite-group-collection.md %}).

### Assigning roles

In order for Forseti to have access to read data from your GCP environment, you will need 
to assign roles to a particular _member_: either the Inventory/Scanner/Enforcer 
service account or your Google user. You can refer to the [official documentation about members](https://cloud.google.com/iam/docs/overview#concepts_related_to_identity) for more information.

Also, you can grant the roles on the organization, folder, or project IAM policies.

  * Organization IAM: the member has access to the everything under the organization.
    Your authed account must have the Organization Admin role to assign the role to another member.
    
    The command to add IAM policy bindings to the organization IAM is:

    ```bash
    $ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
       --member=MEMBER_TYPE:MEMBER_NAME --role=ROLE_NAME
    ```

  * Folder IAM: the member has access to everything under a particular folder.
    Your authed account must have the Folder IAM Admin role to assign the role to another member.

    The command to add IAM policy bindings to the folder IAM is:

    ```bash
    $ gcloud alpha resource-manager folders add-iam-policy-binding FOLDER_ID \
       --member=MEMBER_TYPE:MEMBER_NAME --role=ROLE_NAME
    ```

  * Project IAM: the member has access only to a particular project.
    Your authed account must either have the Owner role on the project or Folder IAM Admin.
    
    The command to add IAM policy bindings to the folder IAM is:

    ```bash
    $ gcloud projects add-iam-policy-binding PROJECT_ID \
       --member=MEMBER_TYPE:MEMBER_NAME --role=ROLE_NAME
    ```

The `MEMBER_TYPE` value is either `user`, `group`, `serviceAccount`, or `domain`.

The `MEMBER_NAME` is either a domain (e.g. example.com) or an email address (user@example.com).

Examples of `MEMBER_TYPE:MEMBER_NAME`:

  * user:me@gmail.com
  * serviceAccount:forseti-gcp-reader@your-project-id.iam.gserviceaccount.com
  * group:my-forseti-group@example.com
  * domain:example.com

Use these commands to grant the Forseti roles to your organization IAM policy. If you 
need to assign the roles on the folder or project level, use the commands from above, with 
the roles below.

```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/browser
```
```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/compute.networkViewer
```
```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/iam.securityReviewer
```
```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/appengine.appViewer
```
```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/servicemanagement.quotaViewer
```
```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/cloudsql.viewer
```
```bash
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/compute.securityAdmin
```

_Project Cloud IAM roles_

These are necessary for reading/writing Forseti data in Google Cloud Storage and Cloud SQL.
Do not assign these outside of the project IAM.

```bash
$ gcloud projects add-iam-policy-binding FORSETI_PROJECT_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/storage.objectViewer
```
```bash
$ gcloud rpojects add-iam-policy-binding FORSETI_PROJECT_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/storage.objectCreator
```
```bash
$ gcloud projects add-iam-policy-binding FORSETI_PROJECT_ID \
--member=MEMBER_TYPE:MEMBER_NAME \
--role=roles/cloudsql.client
```

### Enabling APIs

Enable each of the required APIs by running the following command:

  ```bash
  $ gcloud beta service-management enable <API URI>
  ```
  
  {% include docs/required_apis.md %}
