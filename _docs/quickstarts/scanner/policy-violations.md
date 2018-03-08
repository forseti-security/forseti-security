---
title: Scanner Violations
order: 105
---

# {{ page.title }}

When Scanner finds a rule violation, it outputs the data to a Cloud SQL database.

Scanner provides the capability to save violations as a CSV. This CSV can be 
uploaded automatically to a Cloud Storage bucket, or sent as an email notification.
To specify the Cloud Storage output location for the CSV, 
edit the `notifier` section in the `forseti_server_conf.yaml` file. 
You can read more on how to configure the Notifer
[here]({% link _docs/configure/notifier/index.md %})



Below is an example of scanner violation output:

![scanner violation output table](/images/docs/quickstarts/scanner-output.png)