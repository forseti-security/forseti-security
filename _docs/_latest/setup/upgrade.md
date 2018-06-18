---
title: Upgrade
order: 002
---

# {{ page.title }}

This guide explains how to upgrade your Forseti instance.

---

{% capture 1x_upgrade %}

## Important notes

 * We don't support data migration from v1 to v2, so you will need to archive the database manually 
   for future reference if the data is important to you.
 * [Forseti v2 configuration]({% link _docs/latest/configure/general/index.md %}) is different than v1 so 
   you can not replace the v2 configuration file with the v1 configuration file.
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
# Replace <YOUR_V1_BUCKET> with your v1 forseti GCS bucket and
# <YOUR_V2_BUCKET> with your v2 forseti GCS bucket.

gsutil cp gs://<YOUR_V1_BUCKET>/rules/*.yaml gs://<YOUR_V2_BUCKET>/rules
```

### Archiving your Cloud SQL Database

The best way to archive your database is to use Cloud SQL to [export the data 
to a SQL dump file](https://cloud.google.com/sql/docs/mysql/import-export/exporting#mysqldump).

## Difference between v1 configuration and v2 configuration

We will be listing the difference between v1.1.11 configuration anv v2.0.0 server configuration.

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

## What's next

* Customize [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
[Scanner]({% link _docs/latest/configure/scanner/index.md %}).
* Configure Forseti to send
[email notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications-with-sendgrid).
* Enable [G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})
for processing by Forseti.
