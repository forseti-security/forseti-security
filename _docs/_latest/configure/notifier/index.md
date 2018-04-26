---
title: Notifier
order: 300
---

# {{ page.title }}

Notifier can send a variety of notifications to alert you
of Forseti events. You can configure notifications to send to different
channels and in different formats.

### Notification Types

  1. Inventory summary: Count of the resources added in the latest inventory crawl.
  1. Violations: Individual violations that have been found from the latest scanner run. 
  1. Cloud Security Command Center (Cloud SCC) findings: Violations converted to Cloud SCC findings format, that's ingestable by Cloud SCC.
  
### Notification Channels

  1. Email
  1. Slack
  1. Cloud Storage

### Notification Formats

  1. Human-readable data: CSV
  1. Structured data: JSON

## Configuring Notifier

### Inventory Summary

This is a count of what resources have been crawled into Inventory,
and outputted to Cloud Storage bucket.

```yaml
notifier:
    inventory:
      summary:
        enabled: true
        data_format: csv
        gcs_path: gs://path_to_foo_bucket
```

  `true` enables the notification, and `false` disables the notification.
* `data_format`: either `csv` or `json`
* `gcs_path`: The Cloud Storage bucket to upload the inventory summary.


### Violation Notifications

To select how you want Notifier to send violation notifications,
follow the steps below:

1. Open `forseti-security/configs/forseti_conf.yaml`.
1. Navigate to the `notifier` > `resources` section.

On a per-resources basis, the following options are available. You can use
any combination of notifiers for each resource.

* `should_notify`: Whether a violation for each resource should be sent.
  `true` enables the notification, and `false` disables the notification.

* `name`: The name of the notifier you want for each resource. You can specify
  multiple notifiers for each resource.

  The name must match the actual module name for each notifier in 
  `forseti-security/google/cloud/forseti/notifier/notifiers`,
  such as `email_violations.py`

  These notifiers can be:
  1. `email_violations`
  This emails all the violation data via SendGrid. Multiple email recipients are
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
                 sender: forseti-notify@mycompany.org
                 recipient: foo@gmail.com,bar@gmail.com,baz@gmail.com
             - name: slack_webhook_pipeline
               configuration:
                 webhook_url: https://hooks.slack.com/services/foobar
```

### Cloud SCC Findings

Violations can be shared with [Cloud Security Command Center](https://cloud.google.com/security-command-center) on Google Cloud
Platform (GCP).

1. Open `forseti-security/configs/forseti_conf.yaml`.

1. Navigate to the `notifier` > `violation` > `cloud_scc` section.

```yaml
notifier:
    violation:
      cloud_scc:
        enabled: true
        gcs_path: gs://<path to your GCS bucket>
```

* `enabled`: Whether Cloud SCC findings should be sent.
  `true` enables the notification, and `false` disables the notification.
* `gcs_path`: The Cloud Storage bucket to upload Forseti violations as Cloud SCC findings.
  [Sign-up for the Cloud SCC alpha program here!](https://services.google.com/fb/forms/commandcenteralpha/)

## What's next

* Learn how to [set up SendGrid]({% link _docs/latest/configure/email-notification.md %})
  to receive email notifications.
* Learn how to [invoke the Notifier]({% link _docs/latest/use/notifier.md %}).
