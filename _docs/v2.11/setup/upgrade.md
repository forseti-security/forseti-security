---
title: Upgrade
order: 002
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

{% capture 1x_upgrade %}

## Important notes

 * Forseti doesn't support data migration from v1 to v2. If you want to keep the v1 data, you will
   need to manually archive the database.
 * [Forseti v2 configuration]({% link _docs/v2.11/configure/general/index.md %}) is different than v1. You
   can't replace the v2 configuration file with the v1 configuration file.
 * In v2, all resources are inventoried. You won't be able to configure Inventory to include or exclude resources.

## Upgrade to v2

To upgrade your Forseti instance, it's best to run the v1 and v2 instances
side by side:

1. Create a new project.
1. [Install the latest v2 instance]({% link _docs/v2.11/setup/install.md %}).
1. Copy all the rule files from the v1 bucket to the v2 bucket.

After you have the v2 instance working as expected, you can shut down and
clean up the v1 instance.


### Copying rule files from v1 to v2

You can re-use the rule files defined for your v1 instance in v2 by copying them to the v2 buckets.

To copy all the rule files from the v1 bucket to the v2 bucket, run the following command:

```bash
# Replace <YOUR_V1_BUCKET> with your v1 Forseti Cloud Storage bucket and
# <YOUR_V2_BUCKET> with your v2 Forseti Cloud Storage bucket.

gsutil cp gs://<YOUR_V1_BUCKET>/rules/*.yaml gs://<YOUR_V2_BUCKET>/rules
```

### Archiving your Cloud SQL Database

The best way to archive your database is to use Cloud SQL to [export the data
to a SQL dump file](https://cloud.google.com/sql/docs/mysql/import-export/exporting#mysqldump).

## Difference between v1 and v2 configuration

Following are the differences between v1.1.11 configuration and v2.0.0 server configuration:

### Deprecated fields in v2.0.0
* global
    * db_host
    * db_user
    * db_name
    * groups_service_account_key_file
    * max_results_admin_api

* inventory
    * pipelines


### New fields in v2.0.0
* inventory
    * api_quota
        * servicemanagement

* notifier
    * resources
        * notifiers
            * configuration
                * data_format
    * violation
    * inventory

### Updated/Renamed fields in v2.0.0

{: .table .table-striped}
| v1.1.11 | v2.0.0 |
|--------|--------|
| global/domain_super_admin_email | inventory/domain_super_admin_email |
| global/max_admin_api_calls_per_100_seconds | inventory/api_quota/admin |
| global/max_appengine_api_calls_per_second | inventory/api_quota/appengine |
| global/max_bigquery_api_calls_per_100_seconds | inventory/api_quota/bigquery |
| global/max_cloudbilling_api_calls_per_60_seconds | inventory/api_quota/cloudbilling |
| global/max_compute_api_calls_per_second | inventory/api_quota/compute |
| global/max_container_api_calls_per_100_seconds | inventory/api_quota/container |
| global/max_crm_api_calls_per_100_seconds | inventory/api_quota/crm |
| global/max_iam_api_calls_per_second | inventory/api_quota/iam |
| global/max_sqladmin_api_calls_per_100_seconds | inventory/api_quota/sqladmin |
| notifier/resources/pipelines/email_violations_pipeline | notifier/resources/notifiers/email_violations |
| notifier/resources/pipelines/gcs_violations_pipeline | notifier/resources/notifiers/gcs_violations |
| notifier/resources/pipelines/slack_webhook_pipeline | notifier/resources/notifiers/slack_webhook |

To learn more about these fields, see [Configure]({% link _docs/v2.11/configure/general/index.md %}).

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 1.X installations" content=1x_upgrade uid=0 %}

{% capture 2x_upgrade %}

## Upgrade Forseti v2 using deployment manager

If you used the Forseti installer to deploy, the deployment template is in your 
Cloud Storage bucket for the Forseti instance under the `deployment_templates` folder.
The filename will be in the following format: `deploy-forseti-{forseti_instance_type}-{hash}.yaml`,
for example, `deploy-forseti-server-79c4374.yaml`.

### Change deployment properties

1. Review [`deploy-forseti-server.yaml.in`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/deployment-templates/deploy-forseti-server.yaml.in) 
and [`deploy-forseti-client.yaml.in`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/deployment-templates/deploy-forseti-client.yaml.in) 
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

{% capture upgrading_2_0_0_to_2_1_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.1.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.1.0` to checkout version `v2.1.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-1-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-1-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.1.0`.
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-1-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-1-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-1-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-1-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
Follow instructions [here]({% link _docs/v2.11/configure/general/index.md %}#configuring-settings) to 
update the configuration file.  

    **Inventory**
    - Update the `api_quota` section to include `logging`.
    ```
    api_quota:
        ...
        logging:
          max_calls: 1
          period: 1.1
        ...
    ```
    
    **Notifier**
    - Update the `CSCC` section to include `mode` and `organization_id`.
    ```
    notifier:
        ...
        violation:
            cscc:
                enabled: true
                mode: api
                organization_id: organizations/<your_organization_id>
                # gcs_path should begin with "gs://"
                gcs_path: <your_cscc_gcs_path>
        ...
    ```
1. Rule files updates:  
**No changes to the configuration file.**

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.0.0 to 2.1.0" content=upgrading_2_0_0_to_2_1_0 uid=2 %}

{% capture upgrading_2_1_0_to_2_2_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.2.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.2.0` to checkout version `tags/v2.2.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-2-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-2-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.2.0`.
    1. Add the following fields to the compute engine section inside your deployment template.  
    `region` - The region of your VM, e.g. us-central1,  
    `vpc-host-project-id` - VPC host project ID, by default if you are not using VPC, 
    you can default it to your Forseti project ID,  
    `vpc-host-network` - VPC host network, by default if you are not using VPC, you can default it to `default`,  
    `vpc-host-subnetwork`- VPC host subnetwork, by default if you are not using VPC, you can default it to `default`  
    ```
    
    # Compute Engine
    - name: forseti-instance-server
      type: forseti-instance-server.py
      properties:
        # GCE instance properties
        image-project: ubuntu-os-cloud
        image-family: ubuntu-1804-lts
        instance-type: n1-standard-2
        
    
        # ---- V2.2.0 newly added fields ----
        region: **{YOUR FORSETI VM REGION, e.g. us-central1}**
        vpc-host-project-id: {YOUR_FORSETI_PROJECT_ID}
        vpc-host-network: default
        vpc-host-subnetwork: default
    
    
        ...
        run-frequency: ...
        
        ```
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-2-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-1-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment-templates/deploy-forseti-server-xxxxx-2-2-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-2-0.yaml`  
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
**No changes to the configuration file.**
1. Rule files updates:  
**No changes to the configuration file.**

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.1.0 to 2.2.0" content=upgrading_2_1_0_to_2_2_0 uid=3 %}

{% capture upgrading_2_2_0_to_2_3_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.3.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.3.0` to checkout version `v2.3.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment-templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-3-0.yaml`.
1. Open up the deployment template `deployment_templates/deploy-forseti-server-xxxxx-2-3-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.3.0`.
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-3-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-3-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-3-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-3-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
Follow instructions [here]({% link _docs/v2.11/configure/general/index.md %}#configuring-settings) to 
update the configuration file.   

    **Scanner**
    - Update the `scanners` section to include `log_sink`.
    ```
    scanner:
    ...
        scanners:
            ...
            - name: log_sink
              enabled: true
            ...
    ```
    
    **Notifier**
    - Update the `resources` section to include `log_sink_violations`.
    ```
    notifier:
        ...
        resources:
            ...
            - resource: log_sink_violations
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
            ...
        ...
    ```
1. Rule files updates:  
    1. Add [Log Sink rule file](https://github.com/GoogleCloudPlatform/forseti-security/blob/v2.3.0/rules/log_sink_rules.yaml)
    to `rules/` under your Forseti server GCS bucket to use the LogSink scanner.
    1. BigQuery rule syntax has been [updated (backward compatible)]({% link _docs/v2.11/configure/scanner/rules.md %}#bigquery-rules).

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.2.0 to 2.3.0" content=upgrading_2_2_0_to_2_3_0 uid=4 %}

{% capture upgrading_2_3_0_to_2_4_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.4.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.4.0` to checkout version `v2.4.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-4-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-4-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.4.0`.
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-4-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-4-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-4-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-4-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
Forseti is updated to be usable on a non organization resource.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.3.0 to 2.4.0" content=upgrading_2_3_0_to_2_4_0 uid=5 %}

{% capture upgrading_2_4_0_to_2_5_0 %}

Starting v2.5, Forseti Inventory will be integrated with the Cloud 
Asset Inventory (CAI) service when Forseti is first deployed. CAI
integration is supported only if the root resource is `organization`.
  
Below are the steps to upgrade from v2.4.0 to v2.5.0

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.5.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.5.0` to checkout version `v2.5.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-5-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-5-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.5.0`.
    1. (Server only changes) Add the following lines under sections `imports` and `resources` to allow 
    deployment template to create a new GCS bucket to store the CAI data dump. Please update `{BUCKET_LOCATION}` 
    to point to the location of your bucket, e.g. `us-central1`.   
    ```
    imports:
    ...
    - path: storage/bucket_cai.py
      name: bucket_cai.py
    ...
    
    resources:
    ...
    # Cloud Storage
    ...
    - name: forseti-cai-export
      type: bucket_cai.py
      properties:
        location: {BUCKET_LOCATION}
        retention_days: 14
    ...
    ```
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-5-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-5-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-5-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-5-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
    **Inventory**
    
    Special Note: The FORSETI_CAI_BUCKET needs to be in Forseti project.
    - Add `cai` section. 
       ```
       inventory:
       ...
            api_quota:
            ...
           
            cai:
                enabled: true    
                gcs_path: gs://forseti-cai-export
       ...
       ```
    - Add the cloudasset api quota.
        ```
        inventory:
        ...
            api_quota:
            ...
                cloudasset:
                    max_calls: 1
                    period: 1.0
            ...
        ```
    - Update the IAM and logging api quota.
        ```
        inventory:
        ...
            api_quota:
            ...
                iam:
                    max_calls: 90
                    period: 1.0
                logging:
                    max_calls: 9
                    period: 1.0
            ...
        ```
    **Scanner**
    - Update the `scanners` section to include `lien`.
    ```
    scanner:
    ...
        scanners:
            ...
            - name: lien
              enabled: true
            ...
    ```
    
    **Notifier**
    - Update the `resources` section to include `lien_violations`.
    ```
    notifier:
        ...
        resources:
            ...
            - resource: lien_violations
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
            ...
        ...
    ```
1. Forseti server service account roles updates:
   1. Assign role `roles/storage.objectAdmin` to the service account on the CAI bucket.
    ```
    gsutil iam ch serviceAccount:SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com:objectAdmin YOUR_CAI_BUCKET
    ```
    Example:  
    ```
    gsutil iam ch serviceAccount:forseti-server-gcp-637723d@joeupdate210.iam.gserviceaccount.com:objectAdmin gs://forseti-cai-export
    ```

    1. Assign role `roles/cloudasset.viewer` to the service account on the organization level.   
    ```
    gcloud organizations add-iam-policy-binding {ORGANIZATION_ID} --member=serviceAccount:{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com --role=roles/cloudasset.viewer
    ```
    Example:  
    ```
    gcloud organizations add-iam-policy-binding 1234567890 --member=serviceAccount:forseti-server-gcp-ea370bd@my_gcp_project.iam.gserviceaccount.com --role=roles/cloudasset.viewer
    ```
1. Forseti project API updates:
   1. Enable `Cloud Asset API` under APIs & Services from the GUI or by running the following command on cloud shell:  
    `gcloud beta services enable cloudasset.googleapis.com`
1. Create a copy and upload [lien_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/lien_rules.yaml) to `rules` directory under your Forseti server GCS bucket.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.4.0 to 2.5.0" content=upgrading_2_4_0_to_2_5_0 uid=6 %}

{% capture upgrading_2_5_0_to_2_6_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.6.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.6.0` to checkout version `v2.6.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-6-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-6-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.6.0`.
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-6-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-6-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-6-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-6-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
    **Scanner**
    - Update the `scanners` section to include `location`.
    ```
    scanner:
    ...
        scanners:
            ...
            - name: location
              enabled: true
            ...
    ```
    
    **Notifier**
    - Update the `resources` section to include `location_violations`.
    ```
    notifier:
        ...
        resources:
            ...
            - resource: location_violations
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
            ...
        ...
    ```
1. Forseti server service account roles updates:

    1. Assign role `roles/orgpolicy.policyViewer` to the service account on the organization level.   
    ```
    gcloud organizations add-iam-policy-binding {ORGANIZATION_ID} --member=serviceAccount:{SERVICE_ACCOUNT_NAME}@{PROJECT_ID}.iam.gserviceaccount.com --role=roles/orgpolicy.policyViewer
    ```
    Example:  
    ```
    gcloud organizations add-iam-policy-binding 1234567890 --member=serviceAccount:forseti-server-gcp-ea370bd@my_gcp_project.iam.gserviceaccount.com --role=roles/orgpolicy.policyViewer
    ```

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.5.0 to 2.6.0" content=upgrading_2_5_0_to_2_6_0 uid=7 %}

{% capture upgrading_2_6_0_to_2_7_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.7.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
    clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.7.0` to checkout version `v2.7.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS 
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml 
deployment-templates/deploy-forseti-server-xxxxx-2-7-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-7-0.yaml` for edit.
    1. Update the `forseti-version` inside the deployment template to `tags/v2.7.0`.
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-7-0.yaml` back to the GCS bucket 
(`forseti-server-xxxxxx/deployment_templates`) by running command  
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-7-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-7-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and 
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deploy-forseti-server-xxxxx-2-7-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section 
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect.  
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE`  
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-8` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
    **Scanner**
    - Update the `scanners` section to include `ke_scanner`.
    ```
    scanner:
    ...
        scanners:
            ...
            - name: ke_scanner
              enabled: false
            ...
    ```
    
    **Notifier**
    - Update the `resources` section to include `ke_violations`.
    ```
    notifier:
        ...
        resources:
            ...
            - resource: ke_violations
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
            ...
        ...
    ```

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.6.0 to 2.7.0" content=upgrading_2_6_0_to_2_7_0 uid=8 %}

{% capture upgrading_2_7_0_to_2_8_0 %}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.8.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory, 
    run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
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
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
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
1. To enable the [External Project Access Scanner]({% link _docs/v2.11/configure/scanner/descriptions.md %}#external-project-access-scanner), go to your Google Admin
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
    [here](https://github.com/GoogleCloudPlatform/forseti-security/blob/v2.9.0/configs/server/forseti_conf_server.yaml.in)
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
    - Google Groups default rule has been [updated]({% link _docs/v2.11/configure/scanner/rules.md %}#google-group-rules) 
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
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to 
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
    1. Run command `git clone https://github.com/GoogleCloudPlatform/forseti-security.git` to
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
  - Add [KMS rule file](https://github.com/GoogleCloudPlatform/forseti-security/blob/v2.11.0/rules/kms_rules.yaml)
   to `rules/` under your Forseti server GCS bucket to use the KMS scanner.
  - Add [Resource rule file](https://github.com/GoogleCloudPlatform/forseti-security/blob/v2.11.0/rules/resource_rules.yaml)
   to `rules/` under your Forseti server GCS bucket to use the Resource scanner.
  - External Project Access rule syntax has been [updated to include whitelisting users]({% link _docs/v2.11/configure/scanner/rules.md %}#external-project-access-rules).
  
{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.10.0 to 2.11.0" content=upgrading_2_10_0_to_2_11_0 uid=10 %}

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

* Customize [Inventory]({% link _docs/v2.11/configure/inventory/index.md %}) and
[Scanner]({% link _docs/v2.11/configure/scanner/index.md %}).
* Configure Forseti to send
[email notifications]({% link _docs/v2.11/configure/notifier/index.md %}#email-notifications).
* Enable [G Suite data collection]({% link _docs/v2.11/configure/inventory/gsuite.md %})
for processing by Forseti.