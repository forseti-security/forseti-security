---
---
### Create a GCP project
* Create a new project within your Google Cloud Organization.
  * You can also re-use a project that is dedicated for Forseti Security.
  * Ensure billing is enabled for the project.

**Note**: Forseti Security depends on having a GCP organization set up.
Take note of your organization ID, either by looking it up in
your Cloud Console IAM settings or asking your Organization Admin.
You will need to use it as a flag value when running the individual tools.

### Create a service account
{% include install_service_accounts.md %}

### Install `gcloud`
[Download and install](https://cloud.google.com/sdk/gcloud/) `gcloud`.

#### Configure `gcloud`

  ```sh
  $ gcloud components update
  ```
  
Ensure gcloud is configured for your Forseti Security project.

  ```sh
  $ gcloud info

    ... some info ...

  Account: [user@company.com]
  Project: [my-forseti-security-project]

  Current Properties: [core]
      project: [my-forseti-security-project]
      account: [user@company.com]

    ... more info ...
  ```

### Enable required APIs
Use `gcloud` to enable required APIs.

* Enable **Cloud SQL API**.

  ```sh
  $ gcloud beta service-management enable sql-component.googleapis.com
  ```

* Enable **Cloud SQL Admin API**.

  ```sh
  $ gcloud beta service-management enable sqladmin.googleapis.com
  ```

* Enable **Cloud Resource Manager API**.

  ```sh
  $ gcloud beta service-management enable cloudresourcemanager.googleapis.com
  ```

* Enable the **Admin SDK API**

  ```sh
  $ gcloud beta service-management list enable admin.googleapis.com
  ```

{% if page.install_type == 'gcp' %}
    {% include install_gcp_prerequisites.md %}
{% endif %}

### Obtain a SendGrid API Key (optional)
SendGrid is currently the only supported email service provider. To use it,
sign up for a [SendGrid account](https://sendgrid.com) and create a
[General API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html).
You will use this API key in the deployment templates or as a flag value
for the Forseti Security commandline tools.

If you do not want to send email notification, do not specify the
email recipient in the flag or the Deployment Manager yaml.

**Note:** By default, SendGrid includes an invisible tracking pixel in your
emails, which may cause email warnings about opening images. To address this or
if you don't want to be tracked, the tracking pixel can be
[disabled here](https://sendgrid.com/docs/User_Guide/Settings/tracking.html#-Open-Tracking).

{% if page.name == "local" %}
    {% include install_local_prerequisites.md %}
{% endif %}