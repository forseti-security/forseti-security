# Service account
In order to run Forseti Security, you must add a service account
to your **organization-level** IAM policy.

 * [Create a service account](#create-a-service-account)
 * [Enable the required GCP IAM roles](#enable-the-required-gcp-iam-roles)
 * [Enable scanning of GSuite Groups](#enable-scanning-of-gsuite-groups)

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
## Enable the required GCP IAM roles
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

## Enable scanning of GSuite Groups
Forseti supports the scanning GCP projects for granted users that might be a GSuite Google group. Doing this requires taking special steps on the previously created service account and within the GSuite domain.

 1. When creating or editing a previously created service account you must enable Domain-wide Delegation "DWD" ([details](https://cloud.google.com/appengine/docs/flexible/python/authorizing-apps#google_apps_domain-wide_delegation_of_authority)].
 
 * If you intend to run Forseti Security on GCP*
 
 1. You must collect and specify an email address of a super-admin in your GSuite account in the deployment template (details)
 
 * If you intend to run Forseti Security locally*
 
 1. You must pass the an email address of a super-admin in your GSuite account to `inventory` (details)
 1. You must pass the path to the downloaded JSON file of the credentials for the service account to `inventory` (details)
