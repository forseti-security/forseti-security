---
title: Notifier
order: 300
---

# {{ page.title }}

Forseti Notifier can send a variety of notifications to alert you
of Forseti events. These notifications can be configured to be sent
to different channels, and in different formats.

### Notification Types

  1. Inventory summary
  1. Scanner summary
  1. Violations
  1. CSCC findings
  
### Notification Channels

  1. Email
  1. Slack
  1. GCS

### Notification Formats

  1. csv (human-readable data)
  1. json (structured data)

## Configuring Notifier

### Inventory summary(TBD)

### Scanner summary (TBD)

### Violation Notifications

1. Open `forseti-security/configs/forseti_conf.yaml`.
1. Navigate to the `notifier` > `resources` section.

The following options are available, on a per resource basis. You can mix and
match any combination of notifiers for each resource.

This example shows adding a email, slack, and gcs notifer on cloudsql violations.

```
notifier:
    resources:
        - resource: cloudsql_acl_violations
          should_notify: true
          pipelines:
             # Upload violations to GCS.
             - name: gcs_violations_pipeline
               configuration:
                 # gcs_path should begin with "gs://"
                 gcs_path: gs://inventoryscanner-henry.appspot.com
             - name: email_violations_pipeline
               configuration:
                 sendgrid_api_key: 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
                 sender: forseti-notify@forsetisecurity.org
                 recipient: goldspin@gmail.com
```

* `should_notify`: Controls whether violation for each resource should be sent.
  `true` enables the notification, and `false` disables the notification.

* `name`: The desired notifiers for each resource.  You can specify multiple
  notifiers for each resource.

  The name must match the actual module name for each notifier in 
  `forseti-security/google/cloud/forseti/notifier/notifiers`,
  e.g. `email_violations.py`

  These notifiers can be:
  1. `email_violations`
  This emails all the violation data via SendGrid.  Multiple email recipients are
  delimited by comma.

  1. `slack_webhook`
  This sends individual violations to a Slack channel via a Slack webhook.
  Configure a webhook in your organization's Slack settings and set the `webhook_url`.

  1. `gcs_violations`
  This uploads all the violation data to a GCS bucket.

* `data_format`: Either `csv` (default) or `json`.
  Slack only support json type.

### CSCC Findings

Forseti violations can be outputted for integration with
[Cloud Security Command Center](https://cloud.google.com/security-command-center) on GCP.

1. Open `forseti-security/configs/forseti_conf.yaml`.

1. Navigate to the `notifier` > `violation` > `cscc` section.

```
notifier:
    violation:
      cscc:
        enabled: true
        gcs_path: gs://inventoryscanner-henry.appspot.com
```

* `enabled`: Controls whether CSCC findings should be sent.
  `true` enables the notification, and `false` disables the notification.
* `gcs_path`: The GCS bucket to upload Forseti violations as CSCC findings.
  [Sign-up for the Cloud SCC alpha program here!](outputted for integration with Cloud Security Command Center on GCP. Sign-up for the Cloud SCC alpha program here!)


## Usage

Forseti Notifier can be invoked in 2 ways, as part of the scheduled cron job's
workflow, or manually via the Forseti CLI.

When the cron job runs the Notifier, it will send notifications on the
latest violations from the previous scanner run.

When using the CLI, you can use flags to specify the violations that
the notifier will run on.

  * In the Foseti VM:
  ```bash
  $ forseti notifier --help
  
  # Send the violations from the last successful scanner run.
  $ forseti notifier run

  # Send the violations by inventory index id.
  $ forseti notifier run --inventory_index_id <inventory index id>

  # Send the violations by scanner index id.
  $ forseti notifier run --scanner_index_id <scanner index id>
  ```

## What's next

- Read more about
  [Configure a sendgrid key]({% link _docs/latest/configure/email-notification.md %}).
