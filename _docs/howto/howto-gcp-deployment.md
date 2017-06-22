# Deploying Forseti on Google Cloud Platform

This page explains how to use the Google Cloud Deployment Manager (DM) to set
up Forseti for your Google Cloud Platform (GCP) resources. The DM templates
help you manage configuration for Forseti Inventory and Scanner. It doesn't
currently schedule or execute Enforcer. You'll use DM to do the following:

  - Create a Cloud SQL instance and database to store Inventory data.
  - Create a Cloud Storage bucket for Scanner output.
  - Create a Google Compute Engine instance to deploy and run Forseti Security.
  - Manage Forseti Security configuration and automatically run Forseti
  Inventory and Scanner.

## Before you begin

To complete this quickstart, you will need:

  - A GCP project for Forseti Security with billing enabled.
  - A GCP organization.

## Setting up Forseti Security

{% capture include_content %}
{% include howto_prereqs_include.md %}
{% endcapture %}

### Customizing deployment templates

Make a copy of `deploy-forseti.yaml.sample` as `deploy-forseti.yaml` and update
the following variables:

  - `CLOUDSQL_INSTANCE_NAME`
    - Instance names must start with a letter and consist of lowercase letters,
    numbers, and hyphens, such as "valid-instancename-1".
    - Instance names must be unique and can't be reused for up to 7 days after
    deletion.
    - Read more about [naming guidelines](https://cloud.google.com/sql/docs/mysql/instance-settings#settings-2ndgen).
  - `SCANNER_BUCKET`
    - Add only the bucket name. Don't include `gs://`.
    - Make sure the name conforms to [bucket naming guidelines](https://cloud.google.com/storage/docs/naming).
    - Use the same name for both the Cloud Storage and Compute Engine sections
    in the template.
  - `YOUR_SERVICE_ACCOUNT`: The service account you created to read GCP
  resource data.
  - `YOUR_ORG_ID`: Your organization ID number. You can find it in the
  Organization Cloud IAM settings or ask your Organization Administrator for
  help.

By default, the deployment template retrieves the latest stable branch to set
`release version` and `src-path`. To get a different release archive, change
the following values:

  - `src-path`: the path to the release, such as
  `https://github.com/GoogleCloudPlatform/forseti-security/archive/TAG_NAME.tar.gz`.
    - Tag names start with a "v" and can be found on the
    [forseti-security](https://github.com/GoogleCloudPlatform/forseti-security/tags page).
    - To use the master branch, set `TAG_NAME` to `master`.
  - `release-version `: the tag name, without the "v" prefix.
    - To use the master branch, set this value to "master".

Following are examples of different values for the `src-path` and
`release-version`:

````
# master release:
release-version: "master"
src-path: https://github.com/GoogleCloudPlatform/forseti-security/archive/master.tar.gz

# v1.0 release:
release-version: "1.0"
src-path: https://github.com/GoogleCloudPlatform/forseti-security/archive/v1.0.tar.gz
````

You can also modify the following templates:

  - `inventory/cloudsql-instance.py`: the template for the Google Cloud SQL
  instance.
  - `inventory/cloudsql-database.py`: the template for the Google Cloud SQL
  database.
  - `storage/bucket.py`: the template for the Google Cloud Storage buckets.
  - `forseti-instance.py`: the template for the Compute Engine instance where
  Forseti Security will run.
    - You can customize the startup script.
    - By default, the startup script sets up the environment to install Forseti
    Security and run the tools hourly.
    - Learn more about [Using Startup Scripts](https://cloud.google.com/deployment-manager/docs/step-by-step-guide/setting-metadata-and-startup-scripts).

### Deploying Forseti Security

After you configure your deployment template variables, use the following code
to create a new deployment:

````
gcloud deployment-manager deployments create forseti-security \
  --config PATH_TO/deploy-forseti.yaml
````

To view your deployment details, access the Cloud Console
[Deployment Manager dashboard](https://console.cloud.google.com/deployments).
If you used the default startup script, Forseti Security will also save a CSV
to `gs://SCANNER_BUCKET/scanner_violations/` hourly and email you the Forseti
Inventory and Scanner results.
