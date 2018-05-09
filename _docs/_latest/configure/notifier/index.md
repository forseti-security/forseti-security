---
title: Notifier
order: 300
---

# {{ page.title }}

Notifier can dispatch a variety of messages through various channels
and varying formats alerting you to events in your environment.

## Notification Types

  * Inventory Summary: Count of the resources added in the latest inventory crawl.
  * Violation Notifications: Individual violations that have been found from the latest scanner run. 
  * Cloud SCC Findings: Violations converted to [Cloud SCC (Cloud Security Command Center)](https://cloud.google.com/security-command-center/) findings format, that's ingestable by Cloud SCC.
  
## Notification Channels

  * Email
  * Slack
  * Cloud Storage

## Notification Formats

  * Human-readable data: CSV
  * Structured data: JSON

## Configuring Notifier

### Inventory Summary

This is a count of what resources have been crawled into inventory,
and outputted to a Cloud Storage bucket.

To configure how you want Notifier to send the Inventory Summary,
follow the steps below

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.

1. Navigate to the `notifier` > `inventory` > `summary` section.

* `enabled`
  * **Description**: Whether to send the inventory summary.
  * **Valid values**: one of valid `true` or `false`

* `data_format`
  * **Description**: The format of the data for the inventory summary.
  * **Valid values**: one of valid `csv` or `json`

* `gcs_path`
  * **Description**: The path to a Cloud Storage bucket.
  * **Valid values**: String
  * **Note**: Must start with `gs://`.

```yaml
notifier:
  inventory:
    summary:
      enabled: true
      data_format: csv
      gcs_path: gs://path_to_foo_bucket
```

### Violation Notifications

To configure how you want Notifier to send violation notifications,
follow the steps below:

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.
1. Navigate to the `notifier` > `resources` section.

On a per-resources basis, the following options are available. You can use
any combination of notifiers for each resource.

* `should_notify`
  * **Description**: Whether a violation for each resource should be sent.
  * **Valid values**: one of valid `true` or `false`

* `name`
  * **Description**: The name of the notifier you want for each resource.
  * **Valid values**: The name must match the actual module name for each notifier in [forseti-security/google/cloud/forseti/notifier/notifiers](https://github.com/GoogleCloudPlatform/forseti-security/tree/2.0-dev/google/cloud/forseti/notifier/notifiers), such as `email_violations`, or `slack_webhook`.
  * **Note**: You can specify multiple notifiers for each resource.

* `data_format`
  * **Description**: The format of the data generated for a given violation.
  * **Valid values**: one of valid `csv` or `json`
  * **Note**: Slack only supports the `json` type.

* `gcs_path`
  * **Description**: The path to a Cloud Storage bucket.
  * **Valid values**: String
  * **Note**: Must start with `gs://`.

* `sendgrid_api_key`
  * **Description**: The key used to authorize requests to SendGrid.
  * **Valid values**: String

* `sender`
  * **Description**: The email address of the sender of the email.
  * **Valid values**: String

* `recipient`
  * **Description**: The email addresses of the recipients of the email.
  * **Valid values**: String
  * **Note**: Multiple email recipients as delimited by comma, e.g. `john@mycompany.com,jane@mycompany.com`.

* `webhook_url`
  * **Description**: The url of the Slack channel to receive the notification. 
  * **Valid values**: String
  * **Note**: See [this Slack documentation on how to generate a webhook](https://api.slack.com/incoming-webhooks).

The following example shows how to update a `.yaml` file to add email, Slack,
and Cloud Storage notifier for Cloud SQL violations.

```yaml
notifier:
  resources:
    - resource: cloudsql_acl_violations
      should_notify: true
      notifiers:
        - name: gcs_violations
          configuration:
            data_format: csv
            gcs_path: gs://path_to_foo_bucket
        - name: email_violations
          configuration:
            data_format: csv
            sendgrid_api_key: foobar_key
            sender: forseti-notify@mycompany.org
            recipient: foo@gmail.com,bar@gmail.com,baz@gmail.com
        - name: slack_webhook
          configuration:
            data_format: json
            webhook_url: https://hooks.slack.com/services/foobar
```

### Cloud SCC Findings

Violations can be shared with [Cloud Security Command Center](https://cloud.google.com/security-command-center) on Google Cloud
Platform (GCP).

[Sign-up for the Cloud SCC alpha program here!](https://services.google.com/fb/forms/commandcenteralpha/)

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.

1. Navigate to the `notifier` > `violation` > `cloud_scc` section.

The following options are available.

* `enabled`
  * **Description**: Whether Cloud SCC findings should be sent.
  * **Valid values**: one of valid `true` or `false`

* `gcs_path`
  * **Description**: The path to a Cloud Storage bucket.
  * **Valid values**: String
  * **Note**: Must start with `gs://`.

```yaml
notifier:
  violation:
    cloud_scc:
      enabled: true
      gcs_path: gs://<path to your GCS bucket>
```

## What's next

* Learn how to [set up SendGrid]({% link _docs/latest/configure/email-notification.md %})
  to receive email notifications.
* Learn how to [generate a Slack webhook](https://api.slack.com/incoming-webhooks).
* Learn how to [invoke the Notifier]({% link _docs/latest/use/notifier.md %}).
