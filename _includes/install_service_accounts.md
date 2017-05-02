---
---
There are two service accounts that need to be created:

 1. A service account with special roles added for performing scanning and
 enforcement
 1. A service account with no special role but domain-wide delegation to
 fetch GSuite Google Group information

#### Create a service account for scanning and enforcement
In general, it's highly recommended to create a separate project that contains
your service accounts and limited editors/owners. You can then use those
service accounts in other projects. For more information, refer to
some [best practices](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#best_practices)
for service accounts.

1. Create a custom service account in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
1. Create and download the json key to your local environment.
1. Set an environment variable to configure the [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials) to reference this key.

```sh
$ export GOOGLE_APPLICATION_CREDENTIALS="<path to your service account key>"
```

##### Enable the required GCP IAM roles for the service account
Grant the required roles to the service account.

* Project browser
* Security Reviewer
* Project editor

```sh
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/browser \
  --role=roles/iam.securityReviewer \
  --role=roles/editor
```

#### Create a service account for inventorying of GSuite Google Groups
1. Create a custom service account in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
 1. Enable `domain-wide delegation`.
1. Create and download the json key to your local environment.
1. Note the `domain-wide client-id`, e.g. 1111111111111111111

##### Enable the service account in the GSuite admin control panel
1. Visit the [advanced settings](https://admin.google.com/ManageOauthClients)
portion of the control panel
 1. Specify the `domain-wide client-id` from above
 1. Specify the scope `https://www.googleapis.com/auth/admin.directory.group.readonly`
