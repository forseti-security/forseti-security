---
title: Policy Violations
order: 105
---

# {{ page.title }}

This page describes how Scanner outputs policy violations. When Scanner finds a
policy violation, it always outputs the CSV data to a Cloud SQL database. You
can also configure Scanner to save to save the CSV to a Cloud Storage bucket,
save locally, or send an email notification. To specify a local or Cloud Storage
output location for the CSV, edit the `forseti_conf.yaml` file as follows:

```
# Output path (do not include filename).
# If GCS location, the format of the path should be:
# gs://bucket-name/path/for/output
output_path: OUTPUT_PATH
```

All policy violations are saved to a new violations table in the Cloud SQL database
by default, for every scanner batch run, using the database configurations that
are already in place. The violations table name includes the snapshot timestamp
and you can query the table for each kind of policy violation.
