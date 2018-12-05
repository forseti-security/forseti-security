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
  [forseti-security/google/cloud/forseti/notifier/notifiers]({% link _docs/_latest/develop/reference/google.cloud.forseti.notifier.notifiers.html %}),
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

Cloud SCC API is now in public beta. Please see the steps below to setup
and configure. The previous alpha API will no longer be supported for setup.

#### Prerequisites
1. [Install]({% link _docs/latest/setup/install.md %})
or [upgrade]({% link _docs/latest/setup/upgrade.md %}) Forseti to version 2.8+. 
1. The person performing the onboarding needs the following org-level IAM roles:
- `Organization Admin`
- `Security Center Admin`
1. Cloud SCC Registration Information (after marketplace on-boarding)
- The `source_id` created for your organization.
- The `Security Center Findings` Editor role has been assigned to your Forseti
server service account, on the organization level.

#### Setup
1. Select `Add Security Sources` on the Cloud SCC Beta Dashboard.

1. Find the [Forseti Cloud SCC Connector](https://console.cloud.google.com/marketplace/details/forseti/forseti-security-cloud-scc-connector)
in Cloud Marketplace.

1. Follow the step-by-step on-boarding flow triggered from the Forseti card.
- Choose the project that is hosting Forseti
- Use the existing Forseti server service account (which will be assigned the
`Security Center Findings Editor` role)
- Note: The on-boarding flow will generate a source_id and assign the `Security
  Center Findings Editor` role, which is required to write to the Cloud SCC Beta API
  to surface the findings in the Cloud SCC.

1. Enable the Cloud SCC Beta API in the Forseti project either via either
the UI or API: 
- via the UI (`API & Services ->  Library`)
- via the command line in Cloud Shell `gcloud services enable securitycenter.googleapis.com`
- Note: You will need to have either owner, editor or service management roles
  in the Project in order to enable the API

1. At the org-level, go to `IAM & Admin -> IAM` and verify that the
`Security Center Findings Editor` role has been added to your Forseti server
service account 

1. Enable the  API connector config to Cloud SCC.  Specifically this means,
in the Forseti project server bucket, edit the `configs/forseti_conf_server.yaml`,
 as follows:

- Open `forseti-security/configs/forseti_conf_server.yaml`.
- Navigate to the `notifier` > `violation` > `cscc` section.

  The options below are available for you to configure:

* `enabled:`
  * **Description**: Whether to send notification to Cloud SCC.
  * **Valid values**: one of valid **`true`** or `false`

* `mode:`
  * **Description**: How to send the violations to Cloud SCC.
  * **Valid values**: one of valid **`api`** or `bucket`
  * **Note**: `api` mode will only work if Forseti is [using a service account
  from the Cloud Security Center project](https://cloud.google.com/security-command-center/docs/how-to-programmatic-access).

* `organization_id:`
  * **Description**: The organization id.
  * **Valid values**: String
  * **Note**: Must be in the form of `organizations/12345`. Used only in `api` mode.

* `source_id`
  * **Description**: ID from the Cloud SCC beta on-boarding. **This must be added**
  to use the Beta API integration.
  * **Valid values**: String
  * **Note**: It’s in the form: source_id: <organizations/ORG_ID/sources/SOURCE_ID>

To verify violations appear in the Cloud SCC Beta Dashboard, [run the notifier]({% link _docs/latest/use/cli/notifier.md %})
after you have [built an inventory]({% link _docs/latest/use/cli/inventory.md %})
and [run the scanner]({% link _docs/latest/use/cli/scanner.md %}).

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
* Learn how to [invoke Forseti Notifier]({% link _docs/latest/use/cli/notifier.md %}).
