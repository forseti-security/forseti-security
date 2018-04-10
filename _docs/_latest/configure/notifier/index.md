---
title: Notifier
order: 300
---
# {{ page.title }}

Forseti Notifier can send a variety of notifications to alert you
of Forseti events. These notifications can be configured to be sent
to different channels, and in different formats.

## Notification Types

  1. Inventory crawl summary.
  1. Scanner scan summary.
  1. Violations.
  1. CSCC findings.
  
## Notification Channels

  1. Email
  1. Slack
  1. GCS

## Notification Formats

  1. csv (human-readable data)
  1. json (structured data)

## Configuring Notifier

### Configuring Inventory crawl summary.(TBD)

### Configuring Scanner scan summary. (TBD)

### Configuring Violation Notifications

1. Open `forseti-security/configs/forseti_conf.yaml`.
1. Navigate to the `notifier` > `resources` section.

The following options are available, on a per resource basis. You can mix and
match any combination of notifiers for each resource.

* `should_notify`: controls whether violation for each resource should be sent.
  `true` enables the notification, and `false` disables the notification.

* `name`: the desired notifiers for each resource. The name here matches
  the actual module name for each notifier in 
  `forseti-security/google/cloud/forseti/notifier/notifiers`,
  e.g. `email_violations.py`

  These notifiers can be:
  1. `email_violations`
  Email notifications via SendGrid -- This sends violation data to multiple
  email recipients, as delimited by comma. [Configure a sendgrid key.](- Read more about [configuring Notifier]({% link _docs/v1.1/howto/configure/email-notification.md %}#setting-up-sendgrid).)

  1. `slack_webhook`
  Slack webhook -- This invokes a Slack webhook for each violation found. 
  Configure a webhook in your organization's Slack settings and set the `webhook_url`.

  1. `gcs_violations`
  Upload to GCS -- This uploads the violation data to a GCS bucket.

* `data_format`: either `csv` (default) or `json`

### Configuring CSCC Findings

Forseti violations can now be outputted for integration with
[Cloud Security Command Center](https://cloud.google.com/security-command-center) on GCP.

1. Open `forseti-security/configs/forseti_conf.yaml`.
1. Navigate to the `notifier` > `violation` > `cscc` section.

* `enabled`: controls whether CSCC findings should be sent
  `true` enables the notification, and `false` disables the notification.

* `gcs_path`: the GCS bucket to upload Forseti violations as CSCC findings
  [Sign-up for the Cloud SCC alpha program here!](outputted for integration with Cloud Security Command Center on GCP. Sign-up for the Cloud SCC alpha program here!)


## Usage

Forseti Notifier can be invoked in 2 ways, as part of the scheduled cron job's
workflow, or manually via the Forseti CLI.

When the cron job runs the Notifier, it will send notifications on the
latest violations from the previous scanner run.

When using the CLI, you can use flags to specify the violations that
the notifier will run on.

  1. In the Foseti VM:
  ```bash
  $ forseti notifier --help
  
  # Send the violations from the last successful scanner run.
  $ forseti notifier run

  # Send the violations for the specified notifications
  $ forseti notifier run --inventory_index_id
  ```

## What's next

- Read more about [enabling Email Notifications]({% link _docs/latest/configure/email-notification.md %}).
