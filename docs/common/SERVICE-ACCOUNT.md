# Service account
In order to run Forseti Security, you must add a service account
to your **organization-level** IAM policy.


## Create a Service Account
In general, it's highly recommended to create a separate project that
contains your service accounts and limited editors/owners. You can
then use those service accounts in other projects. For more
information, refer to some
[best practices](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#best_practices)
for service accounts.

1. Create a custom service account in the
  [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
  Having a custom service account with only the IAM permissions needed
  for testing would allow you to delete the service account when you are done,
  and delete the key when it is no longer needed. A custom service
  account (separate from your user account) will be less likely to be phished
  and easier to clean up than the default service account.
1. Create and download the json key to your local environment.
1. Set an environment variable to configure the
  [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)
  to reference this key.

```sh
$ export GOOGLE_APPLICATION_CREDENTIALS="<path to your service account key>"
```
## Enabling required roles
Grant the required roles to the service account.

```sh
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/browser \
  --role=roles/iam.securityReviewer \
  --role=roles/editor
```
