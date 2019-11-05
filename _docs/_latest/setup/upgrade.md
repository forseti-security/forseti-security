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

{% capture upgrading_2_20_0_to_2_21_0 %}

You can upgrade from 2.20.0 to 2.21.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-20-0-to-2-21-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.21.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.21.0` to checkout version `v2.21.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-21-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-21-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.21.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-21-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-21-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-21-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-21-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
   **Inventory**
   - Add Bigtable Cluster, Instance and Table as Cloud Asset Inventory assets.
      ```
        inventory:
            ...
            cai:
                 ...
                 #asset_types:
                    #    - bigtableadmin.googleapis.com/Cluster
                    #    - bigtableadmin.googleapis.com/Instance
                    #    - bigtableadmin.googleapis.com/Table
            ...
      ```

### Steps to upgrade using Terraform {#tf-upgrade-2-20-0-to-2-21-0}

1. Update the `version` inside `main.tf` file to `4.2.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.20.0 to 2.21.0" content=upgrading_2_20_0_to_2_21_0 uid=22 %}

{% capture upgrading_2_21_0_to_2_22_0 %}

You can upgrade from 2.21.0 to 2.22.0 using Deployment Manager or Terraform. 

### Steps to upgrade using Deployment Manager {#dm-upgrade-2-21-0-to-2-22-0}

1. Open cloud shell when you are in the Forseti project on GCP.
1. Checkout forseti with tag v2.22.0 by running the following commands:
    1. If you already have the forseti-security folder under your cloud shell directory,
   run command `rm -rf forseti-security` to delete the folder.
    1. Run command `git clone https://github.com/forseti-security/forseti-security.git` to
   clone the forseti-security directory to cloud shell.
    1. Run command `cd forseti-security` to navigate to the forseti-security directory.
    1. Run command `git checkout tags/v2.22.0` to checkout version `v2.22.0` of Forseti Security.
1. Download the latest copy of your Forseti server deployment template file from the Forseti server GCS
bucket to your cloud shell (located under `forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp gs://YOUR_FORSETI_GCS_BUCKET/deployment_templates/deploy-forseti-server-<LATEST_TEMPLATE>.yaml
deployment-templates/deploy-forseti-server-xxxxx-2-22-0.yaml`.
1. Open up the deployment template `deployment-templates/deploy-forseti-server-xxxxx-2-22-0.yaml` for edit.
  1. Update the `forseti-version` inside the deployment template to `tags/v2.22.0`.
  
1. Upload file `deployment-templates/deploy-forseti-server-xxxxx-2-22-0.yaml` back to the GCS bucket
(`forseti-server-xxxxxx/deployment_templates`) by running command 
`gsutil cp deployment-templates/deploy-forseti-server-xxxxx-2-22-0.yaml gs://YOUR_FORSETI_GCS_BUCKET/
deployment_templates/deploy-forseti-server-xxxxx-2-22-0.yaml`.
1. Navigate to [Deployment Manager](https://console.cloud.google.com/dm/deployments) and
copy the deployment name for Forseti server.
1. Run command `gcloud deployment-manager deployments update DEPLOYMENT_NAME --config deployment-templates/deploy-forseti-server-xxxxx-2-22-0.yaml`
If you see errors while running the deployment manager update command, please refer to below section
`Error while running deployment manager` for details on how to workaround the error.
1. Reset the Forseti server VM instance for changes in startup script to take effect. 
You can reset the VM by running command `gcloud compute instances reset MY_FORSETI_SERVER_INSTANCE --zone MY_FORSETI_SERVER_ZONE` 
Example command: `gcloud compute instances reset forseti-server-vm-70ce82f --zone us-central1-c`
1. Repeat step `3-9` for Forseti client.
1. Configuration file `forseti_conf_server.yaml` updates:  
   **Inventory**
   - Add Compute Security Policy to the Cloud Asset Inventory asset types.
      ```
        inventory:
            ...
            cai:
                 ...
                 #asset_types:
                    #    - compute.googleapis.com/SecurityPolicy
            ...
      ```

### Steps to upgrade using Terraform {#tf-upgrade-2-21-0-to-2-22-0}

1. Update the `version` inside `main.tf` file to `4.3.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.21.0 to 2.22.0" content=upgrading_2_21_0_to_2_22_0 uid=23 %}

{% capture upgrading_2_22_0_to_2_23_0 %}

### Steps to Migrate from Deployment Manager
If your Forseti deployment was previously deployed with Deployment Manager, please see the [migration documentation]({% link _docs/latest/setup/migrate.md %}) on migrating to Terraform.  Following these steps will also result in an upgraded deployment of Forseti.

### Steps to Upgrade using Terraform
A Cloud Shell walkthrough is provided to assist with upgrading Forseti previously deployed with Terraform.  Completing this guide will also result in a Forseti deployment upgraded to the most recent version.

[![Open in Cloud Shell](https://gstatic.com/cloudssh/images/open-btn.svg)](https://console.cloud.google.com/cloudshell/open?cloudshell_git_repo=https%3A%2F%2Fgithub.com%2Fforseti-security%2Fterraform-google-forseti.git&cloudshell_git_branch=module-release-5.0.0&cloudshell_working_dir=examples/upgrade_forseti_with_v5.0&cloudshell_image=gcr.io%2Fgraphite-cloud-shell-images%2Fterraform%3Alatest&cloudshell_tutorial=.%2Ftutorial.md)

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.22.0 to 2.23.0" content=upgrading_2_22_0_to_2_23_0 uid=24 %}

{% capture upgrading_2_23_0_to_2_24_0 %}

### Forseti on-GCE
1. Update the `version` inside `main.tf` file to `5.1.0`.
1. Run command `terraform init` to initialize terraform.
1. Run command `terraform plan` to see the infrastructure plan.
1. Run command `terraform apply` to apply the infrastructure build.

### Forseti on-GKE
1. Update the `version` inside `main.tf` file to `5.1.0`.
2. Run command `terraform init` to initialize terraform.
3. If you previously configured Config Validator in your module by setting the following values:
```
  config_validator_enabled = true
  git_sync_private_ssh_key_file = ""
  policy_library_repository_url = ""
```
You will need to specify an additional value in your `main.tf` to maintain the periodic git-sync feature for the library:
```
  policy_library_sync_enabled   = true
```
4. Run command `terraform plan` to see the infrastructure plan.
5. Run command `terraform apply` to apply the infrastructure build.

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.23.0 to 2.24.0" content=upgrading_2_23_0_to_2_24_0 uid=25 %}

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

* Customize [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
[Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Configure Forseti to send
[email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications).
* Enable [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
for processing by Forseti.
