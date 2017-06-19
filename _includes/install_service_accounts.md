In order to run Forseti, you need to create two separate service accounts:

 1. A service account with IAM roles that enables Forseti to read GCP data.
 1. A service account with no special role but domain-wide delegation to
 fetch GSuite Google Group information.

It's highly recommended to create a separate project and then create your
Forseti service accounts under that project. This "service accounts project"
should also limit the number of users who have Editor or Owner roles.
You can still use the service accounts in other projects.

For more best practices on creating and configuring service accounts, please
refer to the [official documentation](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#best_practices).

#### Create the service account for Forseti inventory, scanner, and enforcer.

1. Create a custom service account in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
1. Create and download the json key to your local environment.
1. Set an environment variable to configure the [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) to reference this key.

```sh
$ export GOOGLE_APPLICATION_CREDENTIALS="<path/to/service account key>"
```

##### Grant the required GCP IAM roles for the service account
Grant the required roles to the service account.

* Project browser
* Security Reviewer
* Project editor
* Resource Manager Folder Admin
* Storage Object Admin
* Compute Network Admin

```sh
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/browser
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/compute.networkAdmin
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/editor
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/iam.securityReviewer
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/resourcemanager.folderAdmin
gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/storage.admin
```

#### Create a service account for inventorying of GSuite Google Groups
1. Create a custom service account in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
 1. Enable `domain-wide delegation`.
1. Create and download the json key to your local environment.
1. Note the `domain-wide client-id` (a large number, e.g. 1111111111111111111).

##### Enable the service account in the GSuite admin control panel
You must have the **super admin** role in admin.google.com to do these steps.

1. Go to the [advanced settings](https://admin.google.com/ManageOauthClients)
section of the admin.google.com control panel.
 1. Specify the `domain-wide client-id` (from above)
 1. Specify the scope `https://www.googleapis.com/auth/admin.directory.group.readonly`
