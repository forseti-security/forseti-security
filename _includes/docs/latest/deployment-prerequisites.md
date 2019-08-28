### Setting up gcloud

First, install and configure the gcloud command-line tool to run
the setup commands:

  1. Download and install the [gcloud command-line tool](https://cloud.google.com/sdk/docs/).
  1. Make sure gcloud is configured by running `gcloud info` and check that the
  Account and Project displayed match your Forseti Security project. If it
  doesn't match, run the following commands to configure gcloud for your
  Forseti Security project:
      1. Run `gcloud auth login` and use your Google credentials to authenticate.
      1. Run `gcloud init` and select your Forseti Security project and Google
      account.

### Creating service accounts

If you are setting up a developer environment, it's best to use the credential
from the Forseti service accounts. You can also use your own Google credentials
from when you ran `gcloud auth login`, but your personal credentials might drift
and differ from the Forseti service account.

If you are running Forseti on GCP, you'll need to create service accounts with
Cloud Identity and Access Management (Cloud IAM) roles to allow Forseti to
read GCP data and to manage Forseti modules.

For a detailed explanation of how Forseti Security uses service accounts, see
[Forseti Service Accounts]({% link _docs/latest/concepts/service-accounts.md %}).

To create and grant roles to a service account for Forseti Inventory,
Scanner, and Enforcer, follow the steps below:

  1. Go to the [GCP Console](https://console.cloud.google.com/iam-admin/serviceaccounts)
  and create a new service account.
  1. Create and download a JSON key for the service account.
  1. Run the following command to assume the service account credentials:

  ```bash
  gcloud auth activate-service-account --key-file=PATH/TO/KEYFILE.json
  ```

To enable your service account to collect G Suite data, follow the steps in
[Enabling G Suite Access]({% link _docs/latest/configure/inventory/gsuite.md %}).

### Assigning roles

For Forseti to have access to read data from your GCP environment,
you will need to assign the roles below to the Forseti service account or to
your Google user. It is recommended that you assign roles to the service account,
especially if you run Forseti in multiple environments.

{% include docs/latest/forseti-server-gcp-required-roles.md %}

To grant the roles on the Cloud IAM policies, use the following commands:

  * **Organization**: the member has access to everything under the organization.
    Your authorized account must have the Organization Admin role to assign the role to another member.
    
    To retrieve your organization id, [follow these steps](https://cloud.google.com/resource-manager/docs/creating-managing-organization#retrieving_your_organization_id).

    To add Cloud IAM policy bindings to the Organization, run the following command:

    ```bash
    gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
     --member=MEMBER_TYPE:MEMBER_NAME --role=ROLE_NAME
    ```
    
    For exmple:
    
    ```bash
    gcloud organizations add-iam-policy-binding 000000000001 \
      --member=serviceAccount:service-account-01@my-foo-project.iam.gserviceaccount.com \
      --role=roles/serviceusage.serviceUsageConsumer
    ```

  * **Folder**: the member has access to everything under a particular folder.
    Your authorized account must have the Folder Admin role to assign the role to another member.

    To add Cloud IAM policy bindings to the Folder, run the following command:

    ```bash
    gcloud alpha resource-manager folders add-iam-policy-binding FOLDER_ID \
     --member=MEMBER_TYPE:MEMBER_NAME --role=ROLE_NAME
    ```

  * **Project**: the member has access only to a particular project.
    Your authorized account must have the Owner role on the project or Folder Admin.

    To add Cloud IAM policy bindings to the Project, run the following command:

    ```bash
    gcloud projects add-iam-policy-binding PROJECT_ID \
     --member=MEMBER_TYPE:MEMBER_NAME --role=ROLE_NAME
    ```
    
    For example:
    
    ```bash
    gcloud projects add-iam-policy-binding my-project-name \
     --member=serviceAccount:service-account-01@my-project-name.iam.gserviceaccount.com \
     --role=roles/storage.objectCreator
    ```

  * **Service Account**: grant additional roles to the service account.
    Your authorized account must have the Owner role on the project that is
    the source of the service account.

    ```bash
    gcloud iam service-accounts add-iam-policy-binding YOUR_SERVICE_ACCOUNT \
      --member=serviceACcount:YOUR_SERVICE_ACCOUNT --role=ROLE_NAME
    ```

`MEMBER_TYPE`
  * **Description:** identity types in Cloud IAM policies
  * **Valid values:** `user`, `group`, `serviceAccount`, or `domain`

`MEMBER_NAME`
  * **Description:** name of the Cloud IAM member
  * **Valid values:** String, either a domain like example.com, or an email
  address like user@example.com.

Examples of `MEMBER_TYPE:MEMBER_NAME`:

  * user:me@gmail.com
  * serviceAccount:forseti-gcp-reader@your-project-id.iam.gserviceaccount.com
  * group:my-forseti-group@example.com
  * domain:example.com

### Enabling APIs

Enable each of the required APIs by running the following command:

  ```bash
  gcloud services enable <API URI>
  ```

  {% include docs/latest/required-apis.md %}
