---
title: Scanner Violations
order: 105
---

# {{ page.title }}

When Scanner finds a rule violation, it outputs the data to a Cloud SQL database.

Scanner can save violations as a CSV and send an email notification or upload it
automatically to a Cloud Storage bucket. To specify the Cloud Storage output
location for the CSV, edit the `notifier` section in the `forseti_server_conf.yaml`
file. To learn more, see
[Configuring Notifier]({% link _docs/latest/configure/notifier/index.md %})

Below is an example of scanner violation output:

![scanner violation output table](/images/docs/quickstarts/scanner-output.png)
