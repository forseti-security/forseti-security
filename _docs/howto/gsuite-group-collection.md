---
title: Enabling GSuite Google Groups Collection
order: 6
---
#  {{ page.title }}

This page describes how to enable the collection of GSuite Google Groups for
processing by Forseti Scanner and Enforcer.

## Enable Domain-Wide Delegation in GSuite

To enable collection of GSuite Google Groups, follow the steps below to create a
service account just for this functionality:

1.  Create a service account to inventory GSuite Google Groups:
    1.  Go to your
        [Google Cloud Platform console](https://console.cloud.google.com/iam-admin/serviceaccounts) and
        create a new service account.
    1.  Click the "dot" menu on the service account row, then click "Edit". 
        Check "Enable domain-wide delegation", then click "Save".
    1.  Create and download the JSON key to your local environment.
    1.  On the service account row, you should now see a "View Client ID" link. Click it.
        Copy the "Client ID" value, which will be a large number.
1.  Enable the service account in your GSuite admin control panel. You must have
    the **super admin** role in admin.google.com to complete these steps:
    1.  Go to admin.google.com, click the "Security" section, and expand
        [Advanced Settings](https://admin.google.com/ManageOauthClients).
    1.  Paste the **Client ID** you copied above in the "Client Name" field.
    1.  Paste following scope in the "One or More API Scopes" field.
        ```
        https://www.googleapis.com/auth/admin.directory.group.readonly
        ```
    1. Click Authorize.

## Enabling Forseti's GSuite Google Groups collection

After you create a service account above, edit the following variables in your
version of `forseti_conf.yaml`:

-   `groups-domain-super-admin-email`: Use of the Admin API requires delegation
    (impersonation). Enter an email address of a Super Admin in the GSuite
    account.
-   `groups-service-account-key-file`: Forseti Inventory uses this path to
    locate the key file which you downloaded earlier.

## Deploying to GCP with GSuite Google Groups collection

If you
[created a deployment]({% link _docs/quickstarts/forseti-security/index.md %})
on GCP, run the following command to copy your GSuite key to your Forseti instance.

  ```bash
  $ gcloud compute copy-files path/to/service-account-key.json \
      ubuntu@YOUR_INSTANCE_NAME:/home/ubuntu/gsuite_key.json
  ```

Note the remote destination of where you put the key on the VM instance. It
should match what you specified in your forseti_conf.yaml for the
`groups-service-account-key-file` property.
