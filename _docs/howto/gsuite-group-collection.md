---
title: Enabling GSuite Google Groups Collection
order: 5
---
#  {{ page.title }}

This page describes how to enable the collection of GSuite Google Groups for
processing by Forseti Scanner and Enforcer.

## Creating a service account

To enable collection of GSuite Google Groups, follow the steps below to create a
service account just for this functionality:

1.  Create a service account to inventory GSuite Google Groups:
    1.  Go to your
        [Google Cloud Platform console](https://console.cloud.google.com/iam-admin/serviceaccounts) and
        create a new service account.
    1.  Enable `domain-wide delegation`.
    1.  Create and download the JSON key to your local environment.
    1.  Note the `domain-wide client-id`. This will be a large number.
1.  Enable the service account in your GSuite admin control panel. You must have
    the **super admin** role in admin.google.com to complete these steps:
    1.  Go to admin.google.com and access
        [advanced settings](https://admin.google.com/ManageOauthClients).
    1.  Specify the `domain-wide client-id` you noted above.
    1.  Specify the scope
        `https://www.googleapis.com/auth/admin.directory.group.readonly`.

## Enabling GSuite Google Groups collection

After you create a service account above, edit the following variables in your
version of `deploy-forseti.yaml`:

-   `inventory-groups`: set to `true` to enable collection.
-   `groups-domain-super-admin-email`: Use of the Admin API requires delegation
    (impersonation). Enter an email address of a Super Admin in the GSuite
    account.
-   `groups-service-account-key-file`: Forseti Inventory uses this path to
    locate the key file.

If you plan to invoke Forseti Inventory by command-line, use the following
command where `–groups_service_account_key_file` is the path to the
domain-wide-delegation key created for the groups-only service account.

```bash
$ forseti_inventory --config_path PATH_TO_inventory_config \
  --domain_super_admin_email GSUITE_SUPER_ADMIN_EMAIL \
  --groups_service_account_key_file SERVICE_ACCOUNT_KEY
```

## Deploying with GSuite Google Groups collection

After you
[create a deployment]({% link _docs/quickstarts/forseti-security/index.md %}), run the
following commands to complete deployment of GSuite Google Groups collection

```bash
$ gcloud compute copy-files PATH_TO_DOWNLOAD_KEY \
    YOUR_USER@YOUR_INSTANCE_NAME:/tmp/service-account-key.json

$ gcloud compute ssh YOUR_USER@YOUR_INSTANCE_NAME

$ YOUR_INSTANCE_NAME>: sudo mv /tmp/service-account-key.json THE_PATH_YOU_SPECIFIED_IN_DEPLOY_FORSETI.yaml
```

Note the remote destination of where you put the key on the VM instance. It
should match what you specified in your deploy-forseti.yaml for the
`groups-service-account-key-file` property.
