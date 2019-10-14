---
title: Upgrade
order: 003
---

# {{ page.title }}

This guide explains how to upgrade your Forseti instance.

For version 2.0.0 and later, we will provide upgrade instructions from one minor
version to the next minor version. This means, if you want to upgrade from
version 2.2.0 to 2.4.0, you should follow the upgrade instruction for
version 2.2.0 to 2.3.0 first, and then follow the upgrade instruction for
version 2.3.0 to 2.4.0. This ensures the upgrade process is easier to manage
and to test.

---

{% capture 2x_upgrade %}

## Upgrade Forseti v2 using deployment manager

If you used the Forseti installer to deploy, the deployment template is in your 
Cloud Storage bucket for the Forseti instance under the `deployment_templates` folder.
The filename will be in the following format: `deploy-forseti-{forseti_instance_type}-{hash}.yaml`,
for example, `deploy-forseti-server-79c4374.yaml`.

### Change deployment properties

1. Review [`deploy-forseti-server.yaml.in`](https://github.com/forseti-security/forseti-security/blob/master-old/deployment-templates/deploy-forseti-server.yaml.in) 
and [`deploy-forseti-client.yaml.in`](https://github.com/forseti-security/forseti-security/blob/master-old/deployment-templates/deploy-forseti-client.yaml.in) 
for any new properties that you need to copy to your previous deployment template. To compare what's changed, use
the `git diff` command. For example, to see the diff between v2.1.0 and v2.2.0, run:

   ```bash
   $ git diff v2.1.0..v2.2.0 -- deployment-templates/deploy-forseti-server.yaml.in
   ```

1. Edit `deploy-forseti-{forseti_instance_type}-{hash}.yaml` and update the field `forseti-version:` under
section `Compute Engine` to the newest tag. For more information, see [the latest release]({% link releases/index.md %}).

### Run the Deployment Manager update

Run the following update command:

```bash
$ gcloud deployment-manager deployments update DEPLOYMENT_NAME \
  --config path/to/deploy-forseti-{forseti_instance_type}-{HASH}.yaml
```

If you changed the properties in the `deploy-forseti-{forseti_instance_type}-{hash}.yaml` `Compute Engine`
section or the startup script in `forseti-instance.py`, you need to reset the instance for changes 
to take effect:

  ```bash
  $ gcloud compute instances reset COMPUTE_ENGINE_INSTANCE_NAME
  ```

The Compute Engine instance will restart and perform a fresh installation of Forseti. You won't 
need to SSH to the instance to run all the git clone or Python install commands.

Some resources can't be updated in a deployment. If an error displays that you can't
change a certain resource, you'll need to create a new deployment of Forseti.

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).

{% capture upgrading_2_7_0_to_2_8_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.8.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.8.0` to checkout version `v2.8.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-8-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-8-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.8.0`.
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-8-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-8-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-8-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-8-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.7.0 to 2.8.0" content=upgrading_2_7_0_to_2_8_0 uid=9 %}

{% capture upgrading_2_8_0_to_2_9_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.9.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.9.0` to checkout version `v2.9.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-9-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-9-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.9.0`.
    
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-9-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-9-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-9-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-9-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. To enable the [External Project Access Scanner]({% link _docs/v2.20/configure/scanner/descriptions.md %}#external-project-access-scanner), go to your Google Admin
[Manage API client access](https://admin.google.com/ManageOauthClients) Security
settings and add API scope `https://www.googleapis.com/auth/cloudplatformprojects.readonly` 
to the Client ID of your service account.
    ```
    https://www.googleapis.com/auth/admin.directory.group.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly,https://www.googleapis.com/auth/cloudplatformprojects.readonly
    ```
1. Configuration file `forseti_conf_server.yaml` updates:  
    **Inventory**
    - Update the `api_quota` section to include `disable_polling`. 
    Set disable_polling to True to disable polling that API for creation of the inventory.
        ```
        inventory:
            ...
            api_quota:
                ...
                appengine:
                    max_calls: 18
                    period: 1.0
                    disable_polling: False
                ...
                bigquery:
                    max_calls: 160
                    period: 1.0
                    disable_polling: False
                ...
            ...
        ```
    - Update the `cai` section to include any asset types to exclude from the inventory. Refer 
    [here](https://github.com/forseti-security/forseti-security/blob/v2.9.0/configs/server/forseti_conf_server.yaml.in)
    for the full list of assets to exclude. 
    
    - The example below is excluding `google.appengine.Application` and `google.compute.InstanceGroup` from the inventory.
        ```
        inventory:
            ...
            cai:
                ...
                asset_types:
                    - google.appengine.Application
                    - google.compute.InstanceGroup
                ...
            ...
        ```

    **Notifier**
    - Update the `violation` section to include `source_id` where the format is `organizations/ORG_ID/sources/SOURCE_ID`
    to enable CSCC Beta API. Information
    [here.](https://cloud.google.com/blog/products/identity-security/cloud-security-command-center-is-now-in-beta)
    - Update the `resources` section to add the External Project Access Scanner:
        ```
        notifier:
            resources:
                ...
                - resource: external_project_access_violations
                  should_notify: true
                  notifiers:
                    # Email violations
                    - name: email_violations
                        configuration:
                        sendgrid_api_key: {SENDGRID_API_KEY}
                        sender: {EMAIL_SENDER}
                        recipient: {EMAIL_RECIPIENT}
                    # Upload violations to GCS.
                    - name: gcs_violations
                        configuration:
                        data_format: csv
                        # gcs_path should begin with "gs://"
                        gcs_path: gs://{FORSETI_BUCKET}/scanner_violations  
        ```
1. Rule files updates:
    - Google Groups default rule has been [updated]({% link _docs/v2.20/configure/scanner/rules.md %}#google-group-rules) 
    to include Google related service account by default. Add and modify the following to `rules/group_rules.yaml` to enable:
    
    ```
    - name: Allow my company users and gmail users to be in my company groups.
      group_email: my_customer
      mode: whitelist
      conditions:
        - member_email: '@MYDOMAIN.com'
        - member_email: '@gmail.com'
        # GCP Service Accounts
        # https://cloud.google.com/compute/docs/access/service-accounts
        - member_email: "gserviceaccount.com"
        # Big Query Transfer Service
        - member_email: "@bqdts.google.baggins"
    ```
{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.8.0 to 2.9.0" content=upgrading_2_8_0_to_2_9_0 uid=10 %}

{% capture upgrading_2_9_0_to_2_10_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.10.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.10.0` to checkout version `v2.10.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-10-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-10-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.10.0`.
    
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-10-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-10-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-10-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-10-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates: 
    **Inventory**
    - Update the cai section to include the new `api_timeout` field and the
    newly fetched asset:
        ```
        inventory:
            ...
            cai:
                # Timeout in seconds to wait for the exportAssets API to
                # return success.
                # Defaults to 3600 if not set.
                api_timeout: 3600
                
                # If commented out then all currently supported asset types 
                # are exported from Cloud Asset API. The list of default 
                # asset types is in
                # google/cloud/forseti/services/inventory/base/cloudasset.py
                
                #asset_types:
                #   - google.cloud.dataproc.Cluster
                #   - google.cloud.sql.Instance
                #   - google.compute.Project
                #   - google.compute.TargetVpnGateway
                #   - google.compute.VpnTunnel
                #   - google.pubsub.Subscription
                # Timeout in seconds to wait for the exportAssets API to return success.
                # Defaults to 3600 if not set.
                api_timeout: 3600
                
                # If commented out then all currently supported asset types are
                # exported from Cloud Asset API. The list of default asset types is
                # in google/cloud/forseti/services/inventory/base/cloudasset.py
                
                #asset_types:
                #   - google.cloud.sql.Instance
                #   - google.compute.VpnTunnel
                #   - google.pubsub.Subscriptions
        ``` 
        
    **Notifier** 
    - Update the `notifier` section to add the `email_connector` section. 
    Functionality will not change if `email_connector` section isn't added as 
    the code is backward compatible at the moment.
    Example below shows the configuration for SendGrid.
        ```
        notifier:
            email_connector:
                name: sendgrid
                auth:
                  api_key: {SENDGRID_API_KEY}
                sender: {EMAIL_SENDER}
                recipient: {EMAIL_RECIPIENT}
                data_format: csv
        ```
    - Update the `resources` section for all the resources to remove the 
    `configuration` for `Email violations`:
        ```
        notifier:
            resources:
                ...
                - resource: iam_policy_violations
                  should_notify: true
                  notifiers:
                    # Email violations
                    - name: email_violations
                    # Upload violations to GCS.
                    - name: gcs_violations
                        configuration:
                        data_format: csv
                        # gcs_path should begin with "gs://"
                        gcs_path: gs://{FORSETI_BUCKET}/scanner_violations  
        ```
    - If you are making this change, please remove the email configuration 
    from `global` section.
    ```
    global:
        email_recipient: {EMAIL_RECIPIENT}
        email_sender: {EMAIL_SENDER}
        sendgrid_api_key: {SENDGRID_API_KEY}
   ```
   - Please add the placeholder value in the `global` section as shown below:
   ```
   global:
       dummy_key: this_is_just_a_placeholder_see_issue_2486
   ```
1. Update the server service account role at organization level from
 `roles/bigquery.dataViewer` to `roles/bigquery.metadataviewer`.
{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.9.0 to 2.10.0" content=upgrading_2_9_0_to_2_10_0 uid=11 %}

{% capture upgrading_2_10_0_to_2_11_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.11.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.11.0` to checkout version `v2.11.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-11-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-11-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.11.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-11-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-11-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-11-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-11-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates: 
   **Scanner**
   - Update the `scanners` section to include `kms_scanner` and `resource`.
      ```
       scanner:
           ...
           scanners:
               ...
               - name: kms_scanner
                 enabled: true
               ...
               - name: resource
                 enabled: true
               ...
           ...
       ```

   **Notifier**
   - Update the `resources` section to include `kms_violations` and `resource_violations`.
      ```
       notifier:
           resources:
               ...
               - resource: kms_violations
                 should_notify: true
                 notifiers:
                   # Email violations
                   - name: email_violations
                   # Upload violations to GCS.
                   - name: gcs_violations
                       configuration:
                       data_format: csv
                       # gcs_path should begin with "gs://"
                       gcs_path: gs://{FORSETI_BUCKET}/scanner_violations 
               ...
               - resource: resource_violations
                 should_notify: true
                 notifiers:
                   # Email violations
                   - name: email_violations
                   # Upload violations to GCS.
                   - name: gcs_violations
                       configuration:
                       data_format: csv
                       # gcs_path should begin with "gs://"
                       gcs_path: gs://{FORSETI_BUCKET}/scanner_violations 
               ...
           ...
              
       ```
1. Rule files updates:
  - Add [KMS rule file](https://github.com/forseti-security/forseti-security/blob/v2.11.0/rules/kms_rules.yaml)
   to `rules/` under your Forseti server GCS bucket to use the KMS scanner.
  - Add [Resource rule file](https://github.com/forseti-security/forseti-security/blob/v2.11.0/rules/resource_rules.yaml)
   to `rules/` under your Forseti server GCS bucket to use the Resource scanner.
  - External Project Access rule syntax has been [updated to include whitelisting users]({% link _docs/v2.20/configure/scanner/rules.md %}#external-project-access-rules).
  
{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.10.0 to 2.11.0" content=upgrading_2_10_0_to_2_11_0 uid=12 %}

{% capture upgrading_2_11_0_to_2_12_0 %}

You can upgrade from 2.11.0 to 2.12.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-11-0-to-2-12-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.12.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.12.0` to checkout version `v2.12.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-12-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-12-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.12.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-12-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-12-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-12-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-12-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates: 
   **Inventory**
   - Update the `inventory` to include support for `composite_root_resources`.
      ```
       inventory:
            
            # You must set ONLY one of root_resource_id or 
            # composite_root_resources in your configuration. Defining both will 
            # cause Forseti to exit with an error.
           
           ...
            root_resource_id: ROOT_RESOURCE_ID
           
            # Composite root resources: combine multiple resource roots into a
            # single inventory, for use across all the Forseti modules. Can obtain
            # one or more resources from the GCP Resource Hierarchy in any 
            # combination.
            # https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy
            #
            # All resources must grant the appropriate IAM permissions to the 
            # Forseti service account before they can be included in the inventory.
            #
            #Forseti Explain is not supported with a composite root at this time.
            #
            # Resources can exist in multiple organizations
            #
            #composite_root_resources:
            #    - "folders/12345"
            #    - "folders/45678"
            #    - "projects/98765"
            #    - "organizations/56789"

       ```

1. Rule files updates:
  - Update [KMS rule file](https://github.com/forseti-security/forseti-security/blob/v2.12.0/rules/kms_rules.yaml)
    under `rules/` in your Forseti server GCS bucket to be able to use the four
    new use cases that have been added.
  
### Steps to upgrade using Terraform {#tf-upgrade-2-11-0-to-2-12-0}

1. Update the `version` inside `main.tf` file to `1.2.0`.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.
1. Rule files updates:
  - Update [KMS rule file](https://github.com/forseti-security/forseti-security/blob/v2.12.0/rules/kms_rules.yaml)
    under `rules/` in your Forseti server GCS bucket to be able to use the four
    new use cases that have been added.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.11.0 to 2.12.0" content=upgrading_2_11_0_to_2_12_0 uid=13 %}

{% capture upgrading_2_12_0_to_2_13_0 %}

You can upgrade from 2.12.0 to 2.13.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-12-0-to-2-13-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.13.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.13.0` to checkout version `v2.13.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-13-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-13-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.13.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-13-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-13-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-13-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-13-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client. 
 
  
### Steps to upgrade using Terraform {#tf-upgrade-2-12-0-to-2-13-0}

1. Update the version inside main.tf file to 1.3.0.
1. Run command terraform init to get the plugins.
1. Run command terraform plan to see the infrastructure plan.
1. Run command terraform apply to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.12.0 to 2.13.0" content=upgrading_2_12_0_to_2_13_0 uid=14 %}

{% capture upgrading_2_13_0_to_2_14_0 %}

You can upgrade from 2.13.0 to 2.14.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-13-0-to-2-14-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.14.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.14.0` to checkout version `v2.14.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-14-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-14-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.14.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-14-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-14-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-14-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-14-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
   **Inventory**
   - Add api quota for groups settings.
      ```
        inventory:
            ...
            api_quota:
                 ...
                 groupssettings: 
                   max_calls: 5 
                   period: 1.1 
                   disable_polling: False 
            ...
      ```
   **Scanner**
   - Add config validator and groups settings scanners.
      ```
        scanner:
            ...
            scanners:
                - name: config_validator
                  enabled: false
                - name: groups_settings
                  enabled: true
            ...
      ```
   **Notifier**
   - Add config validator and groups settings notification settings.
   - Remove CSCC alpha/beta reference as Forseti is now using the GA API.
      ```
        notifier:
            ...
            resources:
                - resource: config_validator_violations
                  should_notify: true
                  notifiers:
                    # Email violations
                    - name: email_violations
                    # Upload violations to GCS.
                    - name: gcs_violations
                      configuration:
                        data_format: csv
                        # gcs_path should begin with "gs://"
                        gcs_path: gs://<FORSETI_SERVER_BUCKET>/scanner_violations
                - resource: groups_settings_violations
                  should_notify: true
                  notifiers:
                    # Email violations
                    - name: email_violations
                    # Upload violations to GCS.
                    - name: gcs_violations
                      configuration:
                        data_format: csv
                        # gcs_path should begin with "gs://"
                        gcs_path: gs://<FORSETI_SERVER_BUCKET>/scanner_violations
                ...
            violation:
              cscc:
                enabled: true
                # Cloud SCC Beta API uses a new source_id.  It is unique per
                # organization and must be generated via a self-registration process.
                # The format is: organizations/ORG_ID/sources/SOURCE_ID
                source_id: <YOUR_SOURCE_ID>
       ```

1. Rule files updates:
   - Update [KE scanner rule file](https://github.com/forseti-security/forseti-security/blob/v2.14.0/rules/ke_scanner_rules.yaml)
     under `rules/` in your Forseti server GCS bucket to include sample rules according to CIS benchmark.
   - Add [Groups settings rule file](https://github.com/forseti-security/forseti-security/blob/v2.14.0/rules/groups_settings_rules.yaml)
     under `rules/` in your Forseti server GCS bucket to include Groups Settings rules.
1. API updates:
   - Enable Groups Settings API
1. GSuite scope updates:
   - Following the instructions [here](https://developers.google.com/admin-sdk/groups-settings/prerequisites) to enable GSuite API access.
   - Add GSuite scope `https://www.googleapis.com/auth/apps.groups.settings` to your Forseti server service 
     account to allow it to obtain GSuite groups settings data during the inventory process.

### Steps to upgrade using Terraform {#tf-upgrade-2-13-0-to-2-14-0}

1. Update the `version` inside `main.tf` file to `1.4.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.
1. Rule files updates:
  - Update [KE scanner rule file](https://github.com/forseti-security/forseti-security/blob/v2.14.0/rules/ke_scanner_rules.yaml)
    under `rules/` in your Forseti server GCS bucket to include sample rules according to CIS benchmark.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.13.0 to 2.14.0" content=upgrading_2_13_0_to_2_14_0 uid=15 %}

{% capture upgrading_2_14_0_to_2_15_0 %}

You can upgrade from 2.14.0 to 2.15.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-14-0-to-2-15-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.15.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.15.0` to checkout version `v2.15.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-15-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-15-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.15.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-15-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-15-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-15-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-15-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
   **Inventory**
   - Add Global Forwarding Rule and Region Backend Service as Cloud Asset Inventory assets.
      ```
        inventory:
            ...
            cai:
                 ...
                 #asset_types:
                    #    - compute.googleapis.com/GlobalForwardingRule
                    #    - compute.googleapis.com/RegionBackendService
            ...
      ```

1. Rule files updates:
   - Update [gsuite group rules file](https://github.com/forseti-security/forseti-security/blob/release-2.15.0/rules/group_rules.yaml)
     under `rules/` in your Forseti server GCS bucket to exclude gmail as a 
     default whitelisted group

### Steps to upgrade using Terraform {#tf-upgrade-2-14-0-to-2-15-0}

1. Update the `version` inside `main.tf` file to `1.6.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.
1. Update group_rules.yaml rule file under rules/ in your Forseti server GCS bucket to remove the member_email: "@gmail.com" field [here](https://github.com/forseti-security/terraform-google-forseti/blob/master/modules/rules/templates/rules/group_rules.yaml)

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.14.0 to 2.15.0" content=upgrading_2_14_0_to_2_15_0 uid=16 %}

{% capture upgrading_2_15_0_to_2_16_0 %}

You can upgrade from 2.15.0 to 2.16.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-15-0-to-2-16-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.16.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.16.0` to checkout version `v2.16.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-16-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-16-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.16.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-16-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-16-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-16-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-16-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.

### Steps to upgrade using Terraform {#tf-upgrade-2-15-0-to-2-16-0}

1. Update the `version` inside `main.tf` file to `2.1.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.15.0 to 2.16.0" content=upgrading_2_15_0_to_2_16_0 uid=17 %}


{% capture upgrading_2_16_0_to_2_17_0 %}

You can upgrade from 2.16.0 to 2.17.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-16-0-to-2-17-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.17.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.17.0` to checkout version `v2.17.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-17-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-17-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.17.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-17-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-17-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-17-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-17-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Assign role `roles/monitoring.metricWriter` to the service account on the project level.   
```
gcloud projects add-iam-policy-binding {ORGANIZATION_ID} --member=serviceAccount:{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com --role=roles/monitoring.metricWriter
```
Example:  
```
gcloud projects add-iam-policy-binding 1234567890 --member=serviceAccount:forseti-server-gcp-ea370bd@my_gcp_project.iam.gserviceaccount.com --role=roles/monitoring.metricWriter
```
1. Configuration file `forseti_conf_server.yaml` updates: 
   **Inventory**
   - Add Kubernetes resources as Cloud Asset Inventory assets.
      ```
        inventory:
            ...
            cai:
                 ...
                 #asset_types:
                    #    - k8s.io/Namespace
                    #    - k8s.io/Node
                    #    - k8s.io/Pod
                    #    - rbac.authorization.k8s.io/ClusterRole
                    #    - rbac.authorization.k8s.io/ClusterRoleBinding
                    #    - rbac.authorization.k8s.io/Role
                    #    - rbac.authorization.k8s.io/RoleBinding
            ...
      ```

### Steps to upgrade using Terraform {#tf-upgrade-2-16-0-to-2-17-0}

1. Update the `version` inside `main.tf` file to `2.2.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.16.0 to 2.17.0" content=upgrading_2_16_0_to_2_17_0 uid=18 %}


{% capture upgrading_2_17_0_to_2_18_0 %}

You can upgrade from 2.17.0 to 2.18.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-17-0-to-2-18-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.18.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.18.0` to checkout version `v2.18.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-18-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-18-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.18.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-18-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-18-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-18-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-18-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Rule files updates:
   - Update [ke_rules.yaml](https://github.com/forseti-security/forseti-security/blob/release-2.18.0/rules/ke_rules.yaml#L89-L100)
     under `rules/` in your Forseti server GCS bucket to include the latest vulnerable ke versions.

### Steps to upgrade using Terraform {#tf-upgrade-2-17-0-to-2-18-0}

1. Update the `version` inside `main.tf` file to `2.3.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.
1. Rule files updates:
   - Update [ke_rules.yaml](https://github.com/forseti-security/forseti-security/blob/release-2.18.0/rules/ke_rules.yaml#L89-L100)
     under `rules/` in your Forseti server GCS bucket to include the latest vulnerable ke versions.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.17.0 to 2.18.0" content=upgrading_2_17_0_to_2_18_0 uid=19 %}

{% capture upgrading_2_18_0_to_2_19_0 %}

You can upgrade from 2.18.0 to 2.19.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-18-0-to-2-19-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.19.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.19.0` to checkout version `v2.19.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-19-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-19-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.19.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-19-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-19-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-19-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-19-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.

### Steps to upgrade using Terraform {#tf-upgrade-2-18-0-to-2-19-0}

1. Update the `version` inside `main.tf` file to `4.0.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.18.0 to 2.19.0" content=upgrading_2_18_0_to_2_19_0 uid=20 %}

{% capture upgrading_2_19_0_to_2_20_0 %}

You can upgrade from 2.19.0 to 2.20.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-19-0-to-2-20-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.20.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.20.0` to checkout version `v2.20.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-20-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-20-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.20.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-20-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-20-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-20-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-20-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
   **Inventory**
   - Add Address, GlobalAddress and Interconnect as Cloud Asset Inventory assets.
      ```
        inventory:
            ...
            cai:
                 ...
                 #asset_types:
                    #    - compute.googleapis.com/Address
                    #    - compute.googleapis.com/GlobalAddress
                    #    - compute.googleapis.com/ComputeInterconnect
                    #    - compute.googleapis.com/ComputeInterconnectAttachment
            ...
      ```

### Steps to upgrade using Terraform {#tf-upgrade-2-19-0-to-2-20-0}

1. Update the `version` inside `main.tf` file to `4.1.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.19.0 to 2.20.0" content=upgrading_2_19_0_to_2_20_0 uid=21 %}

{% capture deployment_manager_error %}

If you get the following error while running the deployment manager:
```
The fingerprint of the deployment is .....
Waiting for update [operation-xxx-xxx-xxx-xxx]...failed.
ERROR: (gcloud.deployment-manager.deployments.update) Error in Operation [operation-xxx-xxx-xxx-xxx]: errors:
- code: NO_METHOD_TO_UPDATE_FIELD
  message: No method found to update field 'networkInterfaces' on resource 'forseti-server-vm-xxxxx'
    of type 'compute.v1.instance'. The resource may need to be recreated with the
    new field.
```

You can follow the following steps to workaround this deployment manager problem:
1. Copy the compute engine section inside your deployment template and paste it to a text editor.
    ```
    # Compute Engine
    - name: forseti-instance-server
      type: forseti-instance-server.py
      properties:
        # GCE instance properties
        image-project: ubuntu-os-cloud
        image-family: ubuntu-1804-lts
        instance-type: n1-standard-2
        ...
        run-frequency: ...
    ```
1. Remove the compute engine section from the deployment template.
1. Run the deployment manager uppdate command on the updated deployment template.  
`gcloud deployment-manager deployments update DEPLOYMENT_NAME --config forseti_server_v2_x_x.yaml`  
This will remove your VM instance.
1. Paste the compute engine section back to the deployment template, and run the update command again.  
`gcloud deployment-manager deployments update DEPLOYMENT_NAME --config forseti_server_v2_x_x.yaml`  
This will recreate the VM with updated fields.

{% endcapture %}
{% include site/zippy/item.html title="Error while running deployment manager" content=deployment_manager_error uid=50 %}

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.X installations" content=2x_upgrade uid=1 %}

## What's next

* Customize [Inventory]({% link _docs/v2.20/configure/inventory/index.md %}) and
[Scanner]({% link _docs/v2.20/configure/scanner/index.md %}).
* Configure Forseti to send
[email notifications]({% link _docs/v2.20/configure/notifier/index.md %}#email-notifications).
* Enable [G Suite data collection]({% link _docs/v2.20/configure/inventory/gsuite.md %})
for processing by Forseti.
