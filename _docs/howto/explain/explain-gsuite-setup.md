---
title: Enabling GSuite Google Groups Collection For IAM Explain
order: 303
---
#  {{ page.title }}

This page describes how to enable the data collection of G Suite Google Groups and Users for
collecting by IAM Explain.

## Service account creation

1. Go to [Cloud Platform Console Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) 
	and click **Create service account**.
1.  To create and download a JSON key for the service account:
	1.  Click **More** on the service account row, then click **Create key**.
	1.  On the **Create private key** dialog that appears, select **JSON**, then click **Create**.
	1.  In the **Save File** window that appears, save the file to a local directory.

## Copy the service account key to IAM Explain GCE instance

If you deploy the IAM Explain manually and haven't move the service account key to the IAM Explain GCE instance, run the following command to copy your G Suite key to your Forseti instance:

  ```
  gcloud compute scp groups.json \
      ubuntu@host:/home/ubuntu/gsuite.json
  ```
Note that you have to substitute `groups.json` with the proper local json key path/filename.

## Enable Domain-Wide Delegation in G Suite

To enable collection of G Suite Google Groups, follow the steps below to enable Domain-Wide Delegation 
for a service account:
1. Go to [Cloud Platform Console Service Accounts](https://console.cloud.google.com/iam-admin/serviceaccounts) 
	and locate the service account to enable Domain-Wide Delegation. Click the &vellip; next to it.
1. Select **Edit** and then the **Enable G Suite Domain-wide Delegation** checkbox. Save.
1. On the service account row, click **View Client ID**. On the **Client ID for Service account client** panel that appears, copy the **Client ID** value, which will be a large number.
1.  Enable the service account in your G Suite admin control panel. You must have
    the **super admin** role in admin.google.com to complete these steps:
    1.  Go to your Google Admin [Manage API client access](https://admin.google.com/ManageOauthClients)
    Security settings.
    1.  In the **Client Name** box, paste the **Client ID** you copied above.
    1.  In the **One or More API Scopes** box, paste the following scope:
        ```
        https://www.googleapis.com/auth/admin.directory.group.readonly, 
        https://www.googleapis.com/auth/admin.directory.user.readonly
        ```
    1.  Click **Authorize**.


