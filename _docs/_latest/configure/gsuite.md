---
title: G Suite
order: 600
---

#  {{ page.title }}

This page describes how to enable the data collection of G Suite Google Groups for
processing by Forseti Inventory.

---

## Enable Domain-Wide Delegation in G Suite

To enable collection of G Suite Google Groups, follow the steps below to enable your existing forseti
service account for this functionality. Read more about 
[domain-wide delegation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount?hl=en_US#delegatingauthority).

### Enable DwD on a service account

1. Navigate to the [service account](https://pantheon.corp.google.com/projectselector/iam-admin/serviceaccounts){:target="_blank"} page

   * Click on the 3 dots on the right hand side of your Forseti GCP Server service account and select **Edit**
   {% responsive_image path: images/docs/configuration/service_account_edit.png alt: "Service Account Edit" indent: 3 %}
   
   * Select the **Enable G Suite Domain-wide Delegation** checkbox and click **SAVE**
            
{% responsive_image path: images/docs/configuration/service_account_enable_dwd.png alt: "Service Account Enable DwD" indent: 3 %}

1. On the service account row, click **View Client ID**.

1. On the **Client ID for Service account client** panel that appears, copy the **Client ID**
   value, which will be a large number.

{% responsive_image path: images/docs/configuration/client-id.png alt: "service account panel with client ID highlighted" indent: 2 %}
        
### Enable the service account in your G Suite admin control panel.
You must have the **super admin** role in admin.google.com to complete these steps:

1. Go to your Google Admin [Manage API client access](https://admin.google.com/ManageOauthClients)
   Security settings.
1. In the **Client Name** box, paste the **Client ID** you copied above.
1. In the **One or More API Scopes** box, paste the following scope:
    ```
    https://www.googleapis.com/auth/admin.directory.group.readonly
    ```
1. Click **Authorize**.
{% responsive_image path: images/docs/configuration/admin-security.png alt: "manage api client access in Google Admin Security settings" indent: 2 %}

## Configuring Forseti to enable G Suite Google Groups collection

After you create a service account above, you may need to edit the following variables 
in your `forseti_conf_server.yaml`.

- `domain_super_admin_email`: Use of the Admin API requires delegation
  (impersonation). Enter an email address of a Super Admin in the G Suite
  account. If you entered this value in the setup wizard, you do not need to 
  change this in your `forseti_conf_server.yaml`.

If you are running Forseti on GCP and made any changes to the above values, 
you will need to copy the conf file to the GCS bucket. See 
["Move Configuration to GCS"]({% link _docs/latest/configure/forseti/index.md %}) 
for details on how to do this.
