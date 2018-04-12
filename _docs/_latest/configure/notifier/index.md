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
  1. Cloud Security Command Center (Cloud SCC) findings
  
### Notification Channels

  1. Email
  1. Slack
  1. Cloud Storage

### Notification Formats

  1. Human-readable data: .csv
  1. Structured data: JSON

## Configuring Notifier

### Inventory Summary (TBD)

### Scanner Summary (TBD)

### Violation Notifications

To select how you want Notifier to send violation notifications,
follow the steps below:

1. Open `forseti-security/configs/forseti_conf.yaml`.
1. Navigate to the `notifier` > `resources` section.

The following options are available, on a per resource basis. You can mix and
match any combination of notifiers for each resource.

* `should_notify`: Controls whether violation for each resource should be sent.
  `true` enables the notification, and `false` disables the notification.

* `name`: The name of the notifier you want for each resource.  You can specify
  multiple notifiers for each resource.

  The name must match the actual module name for each notifier in 
  `forseti-security/google/cloud/forseti/notifier/notifiers`,
  such as `email_violations.py`

  These notifiers can be:
  1. `email_violations`
  This emails all the violation data via SendGrid.  Multiple email recipients are
  delimited by comma.

  1. `slack_webhook`
  This sends individual violations to a Slack channel via a Slack webhook.
  Configure a webhook in your organization's Slack settings and set the `webhook_url`.

  1. `gcs_violations`
  This uploads all the violation data to a Cloud Storage bucket.

* `data_format`: Either `csv` (default) or `JSON`.
  Slack only support json type.

The following example shows how to update a `.yaml` file to add email, Slack,
and Cloud Storage notifier for Cloud SQL violations:

```yaml
notifier:
    resources:
        - resource: cloudsql_acl_violations
          should_notify: true
          notifiers:
             - name: gcs_violations_pipeline
               configuration:
                 gcs_path: gs://path_to_foo_bucket
             - name: email_violations_pipeline
               configuration:
                 sendgrid_api_key: foobar_key
                 sender: forseti-notify@forsetisecurity.org
                 recipient: foo@gmail.com,bar@gmail.com,baz@gmail.com
             - name: slack_webhook_pipeline
               configuration:
                 webhook_url: https://hooks.slack.com/services/foobar
```

### Cloud SCC Findings

Forseti violations can be output for integration with
[Cloud SCC](https://cloud.google.com/security-command-center) on Google Cloud
Platform (GCP).

1. Open `forseti-security/configs/forseti_conf.yaml`.

1. Navigate to the `notifier` > `violation` > `cloud_scc` section.

```yaml
notifier:
    violation:
      cloud_scc:
        enabled: true
        gcs_path: gs://inventoryscanner-henry.appspot.com
```

* `enabled`: Controls whether Cloud SCC findings should be sent.
  `true` enables the notification, and `false` disables the notification.
* `gcs_path`: The Cloud Storage bucket to upload Forseti violations as Cloud SCC findings.
  [Sign-up for the Cloud SCC alpha program here!](https://services.google.com/fb/forms/commandcenteralpha/)


## Usage

You can invoke Forseti Notifier as part of the scheduled cron job's workflow
or manually using the Forseti CLI.

When the cron job runs the Notifier, it sends notifications on the
latest violations from the previous scanner run.

When you use the CLI, you can use flags to specify the violations that
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
  Learn how to [set up SendGrid]({% link _docs/latest/configure/email-notification.md %})
  to receive email notifications.
