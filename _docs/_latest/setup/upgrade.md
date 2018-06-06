---
title: Upgrade
order: 00
---

# {{ page.title }}

This guide explains how to upgrade your Forseti instance.

---

{% capture 1x_upgrade %}

## Important notes

 * We don't support data migration from v1 to v2, so you will need to archive the database manually 
   for future reference if the data is important to you.
 * [Forseti v2 configuration]({% link _docs/latest/configure/forseti/index.md %}) is different than v1 so 
   you can not replace the v2 configuration file with the v1 configuration file.
 * Configuration of the resources that are inventoried is not configureable.


## Upgrading your v1 instance

The suggested way of upgrading your Forseti instance is to do create a new project, [install 
the latest v2 instance]({% link _docs/latest/setup/install.md %}), move all the rule files 
from the v1 bucket to the v2 bucket.

 
### Moving the rule files from v1 to v2

Since the functionality of the existing scanners didn't change, you can re-use the rule 
files defined for your v1 instance in v2.  

Run the following command to copy all the rule files from the v1 bucket to the v2 bucket.

```bash
# Replace <YOUR_V1_BUCKET> with your v1 forseti GCS bucket and
# <YOUR_V2_BUCKET> with your v2 forseti GCS bucket.

gsutil cp gs://<YOUR_V1_BUCKET>/rules/*.yaml gs://<YOUR_V2_BUCKET>/
```


### Archiving your existing Cloud SQL Database

There are many ways of archiving a database, the recommended way is to [export the data 
to a SQL dump file](https://cloud.google.com/sql/docs/mysql/import-export/exporting#mysqldump) 
through Google Cloud SQL.

{% endcapture %} 
{% include site/zippy/item.html title="Upgrading 1.X installations" content=1x_upgrade uid=0 %}


## What's next

  - Customize [Inventory]({% link _docs/latest/configure/inventory/index.md %}) and
  [Scanner]({% link _docs/latest/configure/scanner/index.md %}).
  - Configure Forseti to send [email notifications]({% link _docs/latest/configure/email-notification.md %}).
  - Enable [G Suite data collection]({% link _docs/latest/configure/gsuite.md %})
  for processing by Forseti.
