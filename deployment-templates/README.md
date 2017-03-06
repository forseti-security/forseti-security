# Deploying Forseti Security to Google Cloud

One of the goals of Forseti Security is to provide continuous scanning and enforcement in your Google Cloud Platform (GCP) environment. [Deployment Manager](https://cloud.google.com/deployment-manager/docs/) (DM) is a Google Cloud service that helps you automate the deployment and management of your GCP resources. We are using DM to do the following:

* Create a CloudSql instance and database for storing Forseti Inventory data.
* Create a GCE instance for deploying Forseti Security.
* Manage configuration for Forseti Security and automatically run the tools.

# Getting started

### Prerequisites
* Install and update `gcloud`. Verify the output of `gcloud info` to determine if your `gcloud` environment is using the right project and username; if not, login and init your environment.

```sh
$ gcloud info

  ... some info ...

Account: [user@company.com]
Project: [my-forseti-security-project]

Current Properties:
  [core]
    project: [my-forseti-security-project]
    account: [user@company.com]

  ... more info ...

```

* Create a new project or use a project that is dedicated for Forseti Security.

* Initialize your `gcloud` commandline environment.

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

### Using Deployment Templates
The provided DM templates are samples for you to use. Make a copy of `deploy-forseti.yaml.sample` as `deploy-forseti.yaml` and update the following variables:

* CLOUDSQL_INSTANCE_NAME
* SCANNER_BUCKET
  * This is just the bucket name; do not include "gs://".
  * Subject to bucket naming restrictions (see below).
* YOUR_SERVICE_ACCOUNT (this can be the application default service account, i.e. `PROJECTNUMBER-compute@developer.gserviceaccount.com`)
* YOUR_ORG_ID (the organization id number)
* YOUR_SENDGRID_API_KEY (the api key for sendgrid email service)
* EMAIL_ADDRESS_OF_YOUR_SENDER (email address of your email sender)
* EMAIL_ADDRESS_OF_YOUR_RECIPIENT (email address of your email recipient)

Note: There are restrictions on bucket names (e.g. they must be unique). Refer to the [bucket naming guidelines](https://cloud.google.com/storage/docs/naming) for more information.

There are other templates that you can modify if you'd like:

* `py/inventory/cloudsql-instance.py`:  The template for the Google Cloud SQL instance.
* `py/inventory/cloudsql-database.py`: The template for the Google Cloud SQL database.
* `py/storage/bucket.py`: The template for the Google Cloud Storage buckets.
* `py/forseti-instance.py`: The template for the Compute Engine instance where Forseti Security will run.
   * You might want to tweak the startup script (more about [startup scripts in GCP docs](https://cloud.google.com/deployment-manager/docs/step-by-step-guide/setting-metadata-and-startup-scripts)).
   * By default, the startup script will setup the environment to install the Forseti Security and run the tools every hour.

### Deploying Forseti Security
After you configure the deployment template variables you can create a new deployment.

```sh
$ gcloud deployment-manager deployments create forseti-security --config deploy-forseti.yaml
```

When your deployment is complete, you can see your deployments in your Cloud Console [Deployment Manager dashboard](https://console.cloud.google.com/deployments). Also, if you're using the default startup script, Forseti Security should run on the top of the hour and drop a csv in `gs://SCANNER_BUCKET/scanner_violations/`.
