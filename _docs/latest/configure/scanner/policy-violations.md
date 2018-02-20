---
title: Scanner Violations
order: 105
---

# {{ page.title }}

When Scanner finds a rule violation, it outputs the data to a Cloud SQL database.

Some Scanners provide the capability to save violations as a CSV. This CSV can be
just a local file, uploaded automatically to a Cloud Storage bucket, or sent as an 
email notification. To specify a local or Cloud Storage
output location for the CSV, edit the `forseti_conf.yaml` file as follows:

```
# Output path (do not include filename).
# If GCS location, the format of the path should be:
# gs://bucket-name/path/for/output
output_path: OUTPUT_PATH
```

All violations are saved to a new violations table in the Cloud SQL database
by default, for every scanner batch run, using the database configurations that
are already in place. The violations table name includes the snapshot timestamp
and you can query the table for each kind of policy violation. Below is an
example of scanner violation output:

![scanner violation output table](/images/docs/quickstarts/scanner-output.png)
