---
title: G Suite
order: 201
---

#  {{ page.title }}

This page describes how to enable the data collection of G Suite for processing
by Forseti Inventory.

---

## Before you begin

To complete this guide and enable a service account in your G Suite admin
control panel, you must have the **super admin** role in admin.google.com.

## Enable Domain-wide Delegation (DwD) in G Suite

To enable collection of G Suite data using your existing Forseti
service account, follow the steps below. Read more about
[domain-wide delegation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount#delegatingauthority).

### Enable DwD on the Forseti server service account

Go to the Google Cloud Platform (GCP) Console 
[Service accounts](https://console.cloud.google.com/projectselector/iam-admin/serviceaccounts){:target="_blank"}
page for the Forseti project and follow the instructions under section `To enable G Suite domain-wide delegation, follow these steps:` 
to enable [domain-wide delegation on the Forseti server service account](https://developers.google.com/admin-sdk/directory/v1/guides/delegation#create_the_service_account_and_credentials).

### Delegate domain-wide authority to the Forseti server service account

Follow [the instructions here](https://developers.google.com/admin-sdk/directory/v1/guides/delegation#delegate_domain-wide_authority_to_your_service_account) 
to grant the Forseti service account the following scopes:
```
https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/cloudplatformprojects.readonly,https://www.googleapis.com/auth/apps.groups.settings
```

## Configuring Forseti to collect G Suite data

After you set up your service account above, you may need to edit the
[`domain_super_admin_email`]({% link _docs/v2.23/configure/inventory/index.md %})
field in your `forseti_conf_server.yaml`.

If you are running Forseti on GCP and made any changes to the above values,
you will need to copy the `conf` file to the Cloud Storage bucket. For more
information, see
[Moving configuration to Cloud Storage]({% link _docs/v2.23/configure/general/index.md %}).

## Troubleshooting

Below are the common errors for GSuite configurations and the steps to be taken
to resolve the errors.

You can find what errors have happened by running `forseti inventory list|get`,
or look at the `inventory_index_errors` column in the `inventory_index` table.

If you make any changes to the `forseti_conf_server.yaml` file, be sure
to update the server by reloading it with `forseti server configuration reload`.

Error:
```
('invalid_grant: Invalid email or User ID', u'{"error" : "invalid_grant", "error_description" : "Invalid email or User ID"}')
```

Solution:
Double-check the email you entered in the `domain_super_admin_email` field of
the `forseti_conf_server.yaml` file. Make sure there is no typo and the user
exists.

***

Error:
```
GCP API Error: unable to get groups from GCP:
<HttpError 403 when requesting https://www.googleapis.com/admin/directory/v1/groups?customer=C04h01n68&alt=json returned "Not Authorized to access this resource/api">
```

Solution:
Make sure you specified a super admin user in the `domain_super_admin_email`
field of the `forseti_conf_server.yaml` file.

***

Error:
```
('unauthorized_client: Client is unauthorized to retrieve access tokens using this method.', u'{"error" : "unauthorized_client", "error_description" : "Client is unauthorized to retrieve access tokens using this method."}')
```

Solution:
Make sure you entered the correct API scope(s) in the GSuite admin console.

***

Error:

No GSuite data and no relevant gsuite error reported by
`forseti inventory list|get` or in `inventory_index_errors` column in the
`inventory_index` table.

Solution:
Make sure DwD is enabled for the server service account.

***

Error:
```
Error calling the IAM signBytes API: {
  "error": {
    "code": 403,
    "message": "Permission iam.serviceAccounts.signBlob is required to perform this operation on service account projects/-/serviceAccounts/forseti-server-gcp-xxxxxx@xyz.iam.gserviceaccount.com.",
    "status": "PERMISSION_DENIED"
  }
}
```

Solution:
Make sure `roles/iam.serviceAccountTokenCreator` is granted to the server
service account.
