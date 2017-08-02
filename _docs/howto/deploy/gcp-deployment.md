---
title: GCP Deployment
order: 102
---
#  {{ page.title }}

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

{% include _howto/deployment_prerequisites.md %}

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

By default, the deployment template retrieves the latest stable branch to set
`release version` and `src-path`. To get a different release archive, change
the following values:

  - `src-path`: the path to the release, such as
  `https://github.com/GoogleCloudPlatform/forseti-security/archive/TAG_NAME.tar.gz`.
    - Tag names start with a "v" and can be found on the
    [forseti-security](https://github.com/GoogleCloudPlatform/forseti-security/tags)
    page.
    - To use the master branch, set `TAG_NAME` to `master`.
  - `release-version `: the tag name, without the "v" prefix.
    - To use the master branch, set this value to "master".

Following are examples of different values for the `src-path` and
`release-version`:

  ```
  # master branch:
  branch-name: "master"
  # release-version: "1.0"
  src-path: https://github.com/GoogleCloudPlatform/forseti-security

  # v1.0 release:
  # branch-name: "master"
  release-version: "1.0"
  src-path: https://github.com/GoogleCloudPlatform/forseti-security
  ```

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

  ```bash
  gcloud deployment-manager deployments create forseti-security \
    --config path/to/deploy-forseti.yaml
  ```

To view your deployment details, access the Cloud Console
[Deployment Manager dashboard](https://console.cloud.google.com/deployments).


### Edit Forseti Configuration

You MUST provide a Forseti configuration file before Forseti will run properly.
Follow the instructions for [configuring Forseti](http://forsetisecurity.org/docs/howto/configure/configuring-forseti) 
to prepare a forseti_conf.yaml.

At the very minimum, you should edit the following values (these are specific 
to GCP deployments and do not necessarily reflect the values you will use for 
other deployments):

* **db_host**: Set this to "localhost" or "127.0.0.1".
* **db_user**: Set this to "root".
* **db_name**: Set this to "forseti_security".
* **output_path**: Set this to gs://YOUR_SCANNER_BUCKET/scanner_violations (where YOUR_SCANNER_BUCKET is the `SCANNER_BUCKET` value you used in deploy-forseti.yaml).
* **rules_path**: Set this to "/home/ubuntu/forseti-security/rules"

### Customize Forseti Rules

Customize your Forseti rules by following [this guide](http://forsetisecurity.org/docs/quickstarts/scanner/rules).

### Move Configuration to GCS

After editing your forseti_conf.yaml, copy it to your GCS `SCANNER_BUCKET`:

```
gsutil cp configs/forseti_conf.yaml gs://YOUR_SCANNER_BUCKET/configs/forseti_conf.yaml
```

Next, copy your rules directory to the GCS `SCANNER_BUCKET`:

```
gsutil cp -r rules gs://YOUR_SCANNER_BUCKET/
```

### Checking the Forseti setup

At this point, Forseti should be installing on the GCE instance that was 
created from the Deployment Manager script. You can ssh into the GCE instance 
and watch the /tmp/deployment.log to watch the progress.

To ssh to your GCE instance, you can either use [`gcloud compute ssh`](https://cloud.google.com/sdk/gcloud/reference/compute/ssh) or go to the GCE 
instance details page from Google Cloud Console > Compute Engine, then click "SSH". 
If a window doesn't pop up right away (or gets blocked), try clicking the SSH 
button again.

Once you're logged into the GCE instance, you can "tail" the deployment log 
(use CTRL-C to exit):

```
tail -f /tmp/deployment.log
```

You can also check out the Stackdriver Log Viewer to see the logs generated by Forseti 
when it runs. Go to Google Cloud Console > Logging > Logs, then set the following dropdowns:

* First dropdown: GCE VM Instance > All instance_id
* Second dropdown: "All logs" or "syslog"


If you run into any issues, especially if deployment.log shows errors, 
please contact the Forseti team at discuss@forsetisecurity.org.
