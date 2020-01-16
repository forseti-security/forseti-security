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
* Cloud Security Command Center

**The possible formats of notifications**
* Human-readable data: CSV
* Structured data: JSON

## Configuring Notifier

### Email Connector Config

Forseti security provides an interface to add the email connector of your
choice. The `email_connector` information will be used when sending out
all email notifications.

To configure `email_connector`, follow the steps below:

1. Open `forseti-security/configs/server/forseti_conf_server.yaml`.
2. Navigate to the `notifier` > `email_connector` section.

If you want the notifier to send violations and/or inventory summary via email, 
provide the corresponding values for all the fields mentioned below.

* `name`
  * **Description**: The connector you want to use to receive emails.
  SendGrid and Mailjet are the only email connector supported at the moment.
  * **Valid values**: sendgrid or mailjet
  
* `auth`
  * **Description**: The authentication/authorization key used to authorize requests to SendGrid or Mailjet.
  * **Valid values**: String
  
* `api_key`
  * **Description**: The key used to authorize requests to SendGrid or Mailjet.
  * **Valid values**: String
  
* `api_secret`
  * **Description**: The secret used to authorize requests to Mailjet. This 
  field is required for Mailjet connector only.
  * **Valid values**: String
  
* `campaign`
  * **Description**: Campaign tag specific for Mailjet. This field is required 
  for Mailjet connector only.
  * **Valid values**: String  
  
* `sender`
  * **Description**: The email address of the sender.
  * **Valid values**: String

* `recipient`
  * **Description**: The email addresses of the recipients.
  * **Valid values**: String
  * **Note**: Multiple email recipients as delimited by comma, for example
  `john@mycompany.com,jane@mycompany.com`.
  
* `data_format`
  * **Description**: The format of the data generated for a given violation, and
  inventory summary.
  * **Valid values**: one of valid `csv` or `json`.
  
#### YAML below shows the email connector config for SendGrid.

To configure other email connector, `name` and `auth` fields should be modified
accordingly.

  ```yaml
  notifier:
    email_connector:
      name: sendgrid
      auth:
        api_key: {SENDGRID_API_KEY}
      sender: {SENDER EMAIL}
      recipient: {RECIPIENT EMAIL}
      data_format: csv
  ```

#### YAML below shows the email connector config for Mailjet.

To configure other email connector, `name` and `auth` fields should be modified
accordingly.

  ```yaml
  notifier:
    email_connector:
      name: mailjet
      auth:
        api_key: {Mailjet_API_KEY}
        api_secret: {Mailjet_API_secret}
        campaign: {Mailjet_Campaign}
      sender: {SENDER EMAIL}
      recipient: {RECIPIENT EMAIL}
      data_format: csv
  ```
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

If you want the notifier to send the inventory summary via email, edit 
`email_summary`:

* `enabled`
  * **Description**: Whether to send the inventory summary.
  * **Valid values**: one of valid `true` or `false`

  ```yaml
  notifier:
    inventory:
      email_summary:
        enabled: true
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
  [forseti-security/google/cloud/forseti/notifier/notifiers](https://github.com/forseti-security/forseti-security/tree/master/google/cloud/forseti/notifier/notifiers),
  such as `email_violations`, or `slack_webhook`.
  * **Note**: You can specify multiple notifiers for each resource.

* `data_format`
  * **Description**: The format of the data for a given violation.
  * **Valid values**: one of valid `csv` or `json`.
  * **Note**: Slack only supports the `json` type.

* `gcs_path`
  * **Description**: The path to a Cloud Storage bucket.
  * **Valid values**: String
  * **Note**: Must start with `gs://`.

* `webhook_url`
  * **Description**: The url of the Slack channel to receive the notification.
  * **Valid values**: String
  * **Note**: See [this Slack documentation on how to generate a webhook](https://api.slack.com/incoming-webhooks).

Note: To send violation notifications via email, you need to use `name`
field only. Connector details needs to be provided in the `email_connector` 
section.

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
        - name: slack_webhook
          configuration:
            data_format: json
            webhook_url: https://hooks.slack.com/services/foobar
```

### Cloud SCC Notification

Forseti Security can configured to send violations to
[Cloud Security Command Center (Cloud SCC)](https://cloud.google.com/security-command-center/).

Cloud SCC API is now Generally Available (GA). Please see the steps below to 
setup and configure.

#### Prerequisites
1. [Install]({% link _docs/latest/setup/install.md %})
or [upgrade]({% link _docs/latest/setup/upgrade.md %}) Forseti to version 2.14+. 
1. The person performing the onboarding needs the following org-level IAM roles:
- `Organization Admin`
- `Security Center Admin`
- `Security Center Sources Admin`
- `Service Account Admin`

#### Setup
1. Select `Add Security Sources` on the Cloud SCC Dashboard.

1. Find the [Forseti Cloud SCC Connector](https://console.cloud.google.com/marketplace/details/forseti/forseti-security-cloud-scc-connector)
in Cloud Marketplace.

1. Follow the step-by-step on-boarding flow triggered from the Forseti card.
- Choose the project that is hosting Forseti
- Use the existing Forseti server service account (which will be assigned the
`Security Center Findings Editor` role)
- Note: The on-boarding flow will generate a source_id and assign the `Security
  Center Findings Editor` role, which is required to write to the Cloud SCC API
  to surface the findings in the Cloud SCC.

1. Enable the Cloud SCC API in the Forseti project either via either
the UI or API: 
- via the UI (`API & Services ->  Library`)
- via the command line in Cloud Shell `gcloud services enable securitycenter.googleapis.com`
- Note: You will need to have either owner, editor or service management roles
  in the Project in order to enable the API

**Using Deployment Manager**
1. Enable the  API connector config to Cloud SCC.  Specifically, this means
in the Forseti project server bucket, edit the `configs/forseti_conf_server.yaml`,
 as follows:

- Open `forseti-security/configs/forseti_conf_server.yaml` from the GCS bucket.
- Navigate to the `notifier` > `violation` > `cscc` section.

  The options below are available for you to configure:

  * `enabled:`
    * **Description**: Whether to send notification to Cloud SCC.
    * **Valid values**: one of valid `true` or `false`
  
  * `source_id`
    * **Description**: ID from the Cloud SCC on-boarding. **This must be added**
    to use the API integration.
    * **Valid values**: String
    * **Note**: It is in the form: source_id: <organizations/ORG_ID/sources/SOURCE_ID>

**Using Terraform**
1. Enable the  API connector config to Cloud SCC by configuring the following fields in 
your Terraform configuration:

  * `cscc_violations_enabled`
    * **Description**: Whether to send notification to Cloud SCC.
    * **Valid values**: One of valid `true` or `false`
  
  * `cscc_source_id`
    * **Description**: ID from the Cloud SCC on-boarding. **This must be added**
    to use the API integration.
    * **Valid values**: String
    * **Note**: It is in the form: `<organizations/ORG_ID/sources/SOURCE_ID>`

To verify violations appear in the Cloud SCC Dashboard, [run the notifier]({% link _docs/latest/use/cli/notifier.md %})
after you have [built an inventory]({% link _docs/latest/use/cli/inventory.md %})
and [run the scanner]({% link _docs/latest/use/cli/scanner.md %}).

### Email notifications

Forseti Security can send email notifications using the SendGrid or Mailjet API. 
SendGrid is the suggested free email service provider for GCP. For information
about how to get 12,000 free emails every month, see
[Sending email with SendGrid](https://cloud.google.com/appengine/docs/standard/python/mail/sendgrid).

To use SendGrid to send email notifications for Forseti Security, follow the
process below:

1. [Sign up for a SendGrid account](https://sendgrid.com/).
1. Create a general
    [API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html).
1. Edit the `email_connector` section in `forseti_conf_server.yaml` to provide
SendGrid specific details.

Note that SendGrid automatically includes an invisible tracking pixel in your
emails. This may cause email warnings about opening images. To disable this,
disable SendGrid
[Open Tracking](https://sendgrid.com/docs/User_Guide/Settings/tracking.html#-Open-Tracking).

To use Mailjet, you should have a contract with mailjet then collect an API Key, an API secret and optionnaly a campaign name if you want to be able to use a specific campaign tag for foresti.

### Adding a new email connector

1. To add a new email connector of your choice, create the connector specific 
class similar to `sendgrid_connector.py` under 
`google.cloud.forseti.common.util.email`. 
1. This class should inherits the base email connector class, 
base_email_connector.py, and implements the methods to send out emails using 
the new connector that's being added.
1. Update the `EMAIL_CONNECTOR_FACTORY` in `email_factory.py` with the 
new connector and connector specific class that was created.
1. Update the `email_connector` section under `notifier` in 
`forseti_conf_server.yaml` with configuration details of the new connector.

## What's next

* Learn how to [generate a Slack webhook](https://api.slack.com/incoming-webhooks).
* Learn how to [invoke Forseti Notifier]({% link _docs/latest/use/cli/notifier.md %}).
