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

### Enable DwD on a service account

1. Go to the Google Cloud Platform (GCP) Console
[Service accounts](https://console.cloud.google.com/projectselector/iam-admin/serviceaccounts){:target="_blank"}
page.

   1. On the right side of the Forseti GCP server service account row,
   under **Options**, click **More > Edit**.

      {% responsive_image path: images/docs/configuration/service_account_edit.png alt: "Service Account Edit" indent: 3 %}

   1. On the **Edit service account** dialog that appears, select the **Enable
   G Suite Domain-wide Delegation** checkbox, then click **Save**.
   NOTE: You may see a field entitled "Product name for the consent screen". You cannot leave this field blank.

   {% responsive_image path: images/docs/configuration/service_account_enable_dwd.png alt: "Service Account Enable DwD" indent: 3 %}

1. On the service account row, click **View Client ID**.

1. On the **Client ID for Service account client** page that appears, copy the
**Client ID** value, which will be a large number.

{% responsive_image path: images/docs/configuration/client-id.png alt: "service account panel with client ID highlighted" indent: 2 %}

### Enable the service account in your G Suite admin control panel.

1. Go to your Google Admin
[Manage API client access](https://admin.google.com/ManageOauthClients) Security
settings.
1. In the **Client Name** box, paste the **Client ID** you copied above.
1. In the **One or More API Scopes** box, paste the following scope:

    ```
    https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/cloudplatformprojects.readonly
    ```

1. Click **Authorize**.
{% responsive_image path: images/docs/configuration/admin-security.png alt: "manage api client access in Google Admin Security settings" indent: 2 %}

## Configuring Forseti to collect G Suite data

After you set up your service account above, you may need to edit the
[`domain_super_admin_email`]({% link _docs/latest/configure/inventory/index.md %})
field in your `forseti_conf_server.yaml`.

If you are running Forseti on GCP and made any changes to the above values,
you will need to copy the `conf` file to the Cloud Storage bucket. For more
information, see
[Moving configuration to Cloud Storage]({% link _docs/latest/configure/general/index.md %}).

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
