# Service account
In order to run Forseti Security, you must add a service account to your **organization-level** IAM policy with at least the `Browser` role. This allows Forseti Security to perform operations such as listing the projects within your organization.

**Note**: If you also want to audit/enforce organization IAM policies, you'll need to assign the `Organization Administrator` role. Note that this is a very powerful role; if your GCE instance gets compromised, your entire account could also be compromised!

```sh
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/browser

## Create a Service Account
In general, it's highly recommended to create a separate project that contains your service accounts and limited editors/owners. You can then use those service accounts in other projects. For more information, refer to some [best practices](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#best_practices) for service accounts.

1. Create a custom service account in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
Having a custom service account with only the IAM permissions needed
for testing would allow you to delete the service account when you are done,
and delete the key when it is no longer needed. A custom service
account (separate from your user account) will be less likely to be phished
and easier to clean up than the default service account.
2. Grant the following IAM roles to the service account:
    * Project Editor
    * Cloud SQL Editor
3. Create and download the json key to your local environment.
4. Set an environment variable to configure the [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)
to reference this key.
```sh
$ export GOOGLE_APPLICATION_CREDENTIALS="<path to your service account key>"
```
