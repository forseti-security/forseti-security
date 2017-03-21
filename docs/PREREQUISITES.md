# Prerequistes to isntalling Forseti Security
## Common across both installation types
### Create a GCP project with associated billing
* Create a new project in your Cloud Console.
  * You can also re-use a project that is dedicated for Forseti Security.
  * Enable Billing in your project, if you haven't already.

**Note**: Forseti Security depends on having a GCP organization set up. Take note of your organization ID, either by looking it up in your Cloud Console IAM settings or asking your Organization Admin. You will need to use it as a flag value when running the individual tools.

## Enable required APIs

* Enable **Cloud Resource Manager API**

  ```sh
  $ cloud beta service-management enable cloudresourcemanager.googleapis.com
  ```
### Service account
See [SERVICE-ACCOUNT](/docs/SERVICE-ACCOUNT.md)

### Python version
Forseti Security currently works with Python 2.7.

### SendGrid API Key
SendGrid is currently the only supported email service provider. To use it, sign up for a [SendGrid account](https://sendgrid.com) and create a [General API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html). You will use this API key in the deployment templates or as a flag value for the Forseti Security commandline tools.

## Prerequisites to installing on GCP
See [PREREQUISITES-GCP](/docs/PREREQUISITES-GCP.md)

## Preqequisites to installing locally
See [PREREQUISITES-LOCALLY](/docs/PREREQUISITES-LOCALLY.md)
