---
title: Notifier
order: 401
---

# {{ page.title }}

Notifier can dispatch a variety of messages through various channels
and varying formats to you to events in your Google Cloud Platform
(GCP) environment.

---

## Notifications

**Types of notifications**
* Inventory Summary: Count of the resources added in the latest inventory crawl.
* Violation Notifications: Individual violations that have been found from the latest scanner run.
* Cloud SCC Findings: Violations converted to [Cloud SCC (Cloud Security Command Center)](https://cloud.google.com/security-command-center/) findings format, that's ingestable by Cloud SCC.

**Channels used to notify**
* Email
* Slack
* Cloud Storage

**The possible formats of notifications**
* Human-readable data: CSV
* Structured data: JSON

## Configuring Notifier

### Inventory Summary

This is a count of what resources have been crawled into inventory,
and output to a Cloud Storage bucket.

To configure how you want Notifier to send the Inventory Summary,
follow the steps below:

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.

1. Navigate to the `notifier` > `inventory` section.

If you want the notifier to upload the inventory summary to a Cloud Storage
bucket, edit `gcs_summary`:

* `enabled`
  * **Description**: Whether to send the inventory summary.
  * **Valid values**: one of valid `true` or `false`.

* `data_format`
  * **Description**: The format of the data for the inventory summary.
  * **Valid values**: one of valid `csv` or `json`.

* `gcs_path`
  * **Description**: The path to a Cloud Storage bucket.
  * **Valid values**: String
  * **Note**: Must start with `gs://`.

  ```yaml
  notifier:
    inventory:
      gcs_summary:
        enabled: true
        data_format: csv
        gcs_path: gs://path_to_foo_bucket
  ```

If you want the notifier to send the inventory summary via email, edit `email_summary`:

* `enabled`
  * **Description**: Whether to send the inventory summary.
  * **Valid values**: one of valid `true` or `false`

* `sendgrid_api_key`
  * **Description**: The key used to authorize requests to SendGrid.
  * **Valid values**: String

* `sender`
  * **Description**: The email address of the sender of the email.
  * **Valid values**: String

* `recipient`
  * **Description**: The email addresses of the recipients of the email.
  * **Valid values**: String
  * **Note**: Multiple email recipients as delimited by comma, like
  `john@mycompany.com,jane@mycompany.com`.

  ```yaml
  notifier:
    inventory:
      email_summary:
        enabled: true
        sendgrid_api_key: <SENDGRID_API_KEY>
        sender: <SENDER EMAIL>
        recipient: <RECIPIENT EMAIL>
  ```

### Violation Notifications

To configure how you want Notifier to send violation notifications,
follow the steps below:

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.
1. Navigate to the `notifier` > `resources` section.

On a per-resources basis, the options below are available. You can use
any combination of notifiers for each resource.

* `should_notify`
  * **Description**: Whether a violation for each resource should be sent.
  * **Valid values**: one of valid `true` or `false`

* `name`
  * **Description**: The name of the notifier you want for each resource.
  * **Valid values**: The name must match the actual module name for each notifier in
  [forseti-security/google/cloud/forseti/notifier/notifiers]({% link _docs/v2.6/develop/reference/google.cloud.forseti.notifier.notifiers.html %}),
  such as `email_violations`, or `slack_webhook`.
  * **Note**: You can specify multiple notifiers for each resource.

* `data_format`
  * **Description**: The format of the data generated for a given violation.
  * **Valid values**: one of valid `csv` or `json`.
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
and Cloud Storage notifier for Cloud SQL violations:

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

### Cloud SCC Notification

Forseti Security can configured to send violations to
[Cloud Security Command Center (Cloud SCC)](https://cloud.google.com/security-command-center/).

As Cloud SCC is in alpha, you must meet the following additional requirements:
* Your organization is enrolled in the [Cloud SCC alpha program](https://services.google.com/fb/forms/commandcenteralpha/).
* Your Forseti project has been whitelisted to Cloud SCC access. You should
send the Forseti `project name, id and number` to your Cloud SCC contact.
* Enable the `Cloud Security Command Center API` for the Forseti project via
the Cloud Console.
* Add the `securityCenter.editor` role to the Forseti server's service account. 

1. Open `forseti-security/configs/forseti_conf_server.yaml`.
1. Navigate to the `notifier` > `violation` > `cscc` section.

The options below are available for you to configure:

* `enabled:`
  * **Description**: Whether to send notification to Cloud SCC.
  * **Valid values**: one of valid `true` or `false`

* `mode:`
  * **Description**: How to send the violations to Cloud SCC.
  * **Valid values**: one of valid `api` or `bucket`
  * **Note**: `api` mode will only work if Forseti is [using a service account from the Cloud Security Center project](https://cloud.google.com/security-command-center/docs/how-to-programmatic-access).

* `organization_id:`
  * **Description**: The organization id.
  * **Valid values**: String
  * **Note**: Must be in the form of `organizations/12345`. Used only in `api` mode.

* `gcs_path`
  * **Description**: The path to a Cloud Storage bucket.
  * **Valid values**: String
  * **Note**: Must start with `gs://`. Used only in `bucket` mode.

### Email notifications with SendGrid

Forseti Security can send email notifications using the SendGrid API. SendGrid
is the suggested free email service provider for GCP. For information about
how to get 12,000 free emails every month, see
[Sending email with SendGrid](https://cloud.google.com/appengine/docs/standard/python/mail/sendgrid).

To use SendGrid to send email notifications for Forseti Security, follow the
process below:

1. [Sign up for a SendGrid account](https://sendgrid.com/).
1. Create a general
    [API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html).
1. Edit the following in `forseti_conf_server.yaml`:
    1. `email_recipient`
       * **Description**: The Email address of notification recipient.
    1. `email_sender`
       * **Description**: The Sender email address for notifications
    1. `sendgrid_api_key`
       * **Description**: The API key for SendGrid email service.

Note that SendGrid automatically includes an invisible tracking pixel in your
emails. This may cause email warnings about opening images. To disable this,
disable SendGrid
[Open Tracking](https://sendgrid.com/docs/User_Guide/Settings/tracking.html#-Open-Tracking).

## What's next

* Learn how to [generate a Slack webhook](https://api.slack.com/incoming-webhooks).
* Learn how to [invoke Forseti Notifier]({% link _docs/v2.6/use/cli/notifier.md %}).
