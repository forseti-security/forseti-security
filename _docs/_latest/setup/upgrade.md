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
 * [Forseti v2 configuration]({% link _docs/latest/configure/general/index.md %}) is different than v1. You
   can't replace the v2 configuration file with the v1 configuration file.
 * In v2, all resources are inventoried. You won't be able to configure Inventory to include or exclude resources.

## Upgrade to v2

To upgrade your Forseti instance, it's best to run the v1 and v2 instances
side by side:

1. Create a new project.
1. [Install the latest v2 instance]({% link _docs/latest/setup/install.md %}).
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

To learn more about these fields, see [Configure]({% link _docs/latest/configure/general/index.md %}).

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 1.X installations" content=1x_upgrade uid=0 %}

{% capture 2x_upgrade %}

## Upgrade Forseti v2 to a newer version using deployment manager.

Note: If you used the Forseti installer to deploy, you can locate the deployment template in your 
GCS bucket for the forseti instance under folder `deployment_templates`, the filename will have the 
following format: `deploy-forseti-{forseti_instance_type}-{hash}.yaml`, an example would be 
`deploy-forseti-server-79c4374.yaml`.

### Change deployment properties
1. Check `deploy-forseti-server.yaml.sample` and `deploy-forseti-client.yaml.sample` to see if 
there are any new properties that you need to copy over to your previous deployment template. You 
can use `git diff` to compare what changed. For example, to see the diff between the latest (HEAD) 
and one revision ago:

   ```bash
   $ git diff origin..HEAD~1 -- deploy-forseti-server.yaml.sample
   ```

1. Edit `deploy-forseti-{forseti_instance_type}-{hash}.yaml` and update field `forseti-version:` under
section `Comput Engine` to the newest tag. You can find more information about 
[the latest release]({% link releases/index.md %}).

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

The Compute Engine instance will restart and perform a fresh installation of Forseti, so you do
not need to ssh to the instance to run all the git clone/python install commands.

Some resources can't be updated in a deployment. If you see an error that you can't
change a certain resource, you'll need to create a new deployment of Forseti.

Learn more about [Updating a Deployment](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments).

{% endcapture %}
{% include site/zippy/item.html title="Upgrading 2.X installations" content=2x_upgrade uid=1 %}

## What's next

* Customize [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
[Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Configure Forseti to send
[email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications-with-sendgrid).
* Enable [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
for processing by Forseti.