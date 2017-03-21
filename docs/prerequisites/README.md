# Prerequistes to isntalling Forseti Security
  1. [Common steps](#common-steps)
    1. [Create a GCP project](#create-a-gcp-project)
    1. [Create a service account](#create-a-service-account)
    1. [Install gcloud](#install-gcloud)
    1. [Configure gcloud](#configure-gcloud)
    1. [Enable required APIs](#enable-required-apis)
    1. [Obtain a SendGrid API key](#obtain-a-sendgrid-api-key)
  1. [Installation specific prerequisites](#installation-specific-prerequisites)
    1. [GCP installations](#gcp-installations)
    1. [Local installations](#local-installations)

## Common steps
### Create a GCP project
* Create a new project within your Google Cloud Organization.
  * You can also re-use a project that is dedicated for Forseti Security.
  * Ensure billing is enabled for the project.

**Note**: Forseti Security depends on having a GCP organization set up.
Take note of your organization ID, either by looking it up in
your Cloud Console IAM settings or asking your Organization Admin.
You will need to use it as a flag value when running the individual tools.

### Create a service account
See [SERVICE-ACCOUNT](/docs/common/SERVICE-ACCOUNT.md) guide for properly and
securely creating a service account.

### Install `gcloud`
[Download and install](https://cloud.google.com/sdk/gcloud/) `gcloud`.

### Configure `gcloud`

  ```sh
  $ gcloud components update
  ```
Display the currently configured user and project in gcloud to ensure it
is what you expected.

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

## Enable required APIs
Use `gcloud` to enable required APIs.

  ```sh
  $ gcloud init
  ```

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

### Obtain a SendGrid API Key
SendGrid is currently the only supported email service provider. To use it, sign
up for a [SendGrid account](https://sendgrid.com) and create
a [General API Key](https://sendgrid.com/docs/User_Guide/Settings/api_keys.html).
You will use this API key in the deployment templates or as a flag value for
the Forseti Security commandline tools.

## Installation specific prerequisites
### GCP installations
#### Enable required APIs

* Enable **Deployment Manager API**.

  ```sh
  $ gcloud beta service-management enable deploymentmanager.googleapis.com
  ```

### Local installations
See [PREREQUISITES-LOCALLY](/docs/PREREQUISITES-LOCALLY.md)
