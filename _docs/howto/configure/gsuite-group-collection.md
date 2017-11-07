---
title: Enabling GSuite Google Groups Collection
order: 204
---
#  {{ page.title }}

This page describes how to enable the data collection of G Suite Google Groups for
processing by Forseti Inventory.

## Enable Domain-Wide Delegation in G Suite

To enable collection of G Suite Google Groups, follow the steps below to create a
service account just for this functionality. Read more about 
[domain-wide delegation](https://developers.google.com/identity/protocols/OAuth2ServiceAccount?hl=en_US#delegatingauthority).

### Create a service account

**Note:** If you used the setup wizard to setup Forseti, it already creates a G Suite 
service account. You can go directly to the 
[next section]({% link _docs/howto/configure/gsuite-group-collection.md %}#enable-the-service-account-in-your-g-suite-admin-control-panel).

1. Go to
   [Cloud Platform Console Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts)
   and click **Create service account**.

1. On the **Create service account** dialog that appears, set up your service account:

   * Enter a service account name.
   * Select the **Enable G Suite Domain-wide Delegation** checkbox.
   * If you haven't already configured your project's OAuth consent screen, enter a product name
      to display on the consent screen, then click **Create**. To change the product name or add
      details to the consent screen later, edit your
      [OAuth consent screen](https://console.developers.google.com/apis/credentials/consent) settings.
            
      ![create service account window with product name field highlighted](/images/docs/howto/create-service-account.png)
        
1. To create and download a JSON key for the service account:

   * Click **More** on the service account row, then click **Create key**.
      ![more menu with create key highlighted](/images/docs/howto/create-key.png)
   *  On the **Create private key** dialog that appears, select **JSON**, then click **Create**.
   *  In the **Save File** window that appears, save the file to a local directory.

1. On the service account row, click **View Client ID**.

1. On the **Client ID for Service account client** panel that appears, copy the **Client ID**
   value, which will be a large number.
    
   ![service account panel with client ID highlighted](/images/docs/howto/client-id.png)
        
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
   ![manage api client access in Google Admin Security settings](/images/docs/howto/admin-security.png)

## Configuring Forseti to enable G Suite Google Groups collection

After you create a service account above, you may need to edit the following variables 
in your `forseti_conf.yaml`.

- `groups-domain-super-admin-email`: Use of the Admin API requires delegation
  (impersonation). Enter an email address of a Super Admin in the GSuite
  account. If you entered this value in the setup wizard, you do not need to 
  change this in your `forseti_conf.yaml`.
- `groups-service-account-key-file`: Forseti Inventory uses this path to
  locate the key file which you downloaded earlier. If you deployed with the 
  setup wizard, this value is already pre-populated for you.

If you are running Forseti on GCP and made any changes to the above values, 
you will need to copy the conf file to the GCS bucket. See 
["Move Configuration to GCS"]({% link _docs/howto/deploy/gcp-deployment.md %}#move-configuration-to-gcs) 
for details on how to do this.

## Deploying to GCP with G Suite Google Groups collection

If you
[created a deployment]({% link _docs/quickstarts/forseti-security/index.md %})
on GCP, run the following command to copy your G Suite key to your Forseti instance:

  ```
  gcloud compute scp local/path/to/service-account-key.json \
      ubuntu@FORSETI_GCE_INSTANCE_NAME:/home/ubuntu/gsuite_key.json
  ```

Note the remote destination of where you put the key on the VM instance. It
should match what you specified in your forseti_conf.yaml for the
`groups-service-account-key-file` property.
