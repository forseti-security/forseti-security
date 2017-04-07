# Deploying Forseti Security to Google Cloud
* [Prerequisites](#prerequisites)
* [Customize Deployment Templates](#customize-deployment-templates)
* [Customze rules.yaml](#customize-rulesyaml)
* [Deploy Forseti Security](#deploy-forseti-security)
* [Troubleshooting](#troubleshooting)

One of the goals of Forseti Security is to provide continuous scanning
and enforcement in your Google Cloud Platform (GCP)environment.
[Deployment Manager](https://cloud.google.com/deployment-manager/docs/) (DM)
is a Google Cloud service that helps you automate the deployment and
management of your GCP resources. We are using DM to do the following:

* Create a Cloud SQL instance and database for storing inventory data.
* Create a Cloud Storage bucket for scanner output.
* Create a Google Compute Engine (GCE) instance for deploying and running Forseti Security.
* Manage configuration for Forseti Security and automatically run
  the **inventory** and **scanner** modules.

**Note**: The DM templates currently do not schedule or execute the
**enforcer** module.

## Prerequisites
See the [README](/docs/prerequisites/README.md) for prerequisites for installation.

## Customize Deployment Templates
The provided DM templates are samples for you to use. Make a copy of
`deploy-forseti.yaml.sample` as `deploy-forseti.yaml` and update the following variables:

* CLOUDSQL\_INSTANCE\_NAME
  * Instance name must start with a letter and consist of lowercase letters, numbers,
    and hyphens (e.g. "valid-instancename-1", NOT "1\_invalid\_instanceName.com").
    See [naming guidelines](https://cloud.google.com/sql/docs/mysql/instance-settings#settings-2ndgen)
    for more information.
  * Instance name must also be unique. If you delete a Cloud SQL instance
    (either by deleting your deployment or manually through
    gcloud or the Cloud Console), you cannot reuse that instance name
    for up to 7 days.
* SCANNER\_BUCKET
  * This is just the bucket name; do not include "gs://".
  * The bucket name is subject to the [bucket naming guidelines](https://cloud.google.com/storage/docs/naming).
  * **Note**: use the same SCANNER\_BUCKET name for both the "Cloud Storage" and
    "Compute Engine" sections in the template.
* YOUR\_SERVICE\_ACCOUNT
  * This can be the application default service account, i.e.
    `PROJECTNUMBER-compute@developer.gserviceaccount.com`.
  * You must assign the `Browser` role to this service account on
    the **organization-level** IAM policy.
* YOUR\_ORG\_ID (the organization id number; get it from the Organization
  IAM settings or ask your Organization Administrator)
* YOUR\_SENDGRID\_API\_KEY (the API key for SendGrid email service)
* EMAIL\_ADDRESS\_OF_YOUR\_SENDER (email address of your email sender)
* EMAIL\_ADDRESS\_OF\_YOUR\_RECIPIENT (email address of your email recipient)
* `src-path` and `release-version`: The default is to retrieve the
  latest stable branch (currently hardcoded). If you want to get a different
  release archive, e.g. master, change the following:
  * `src-path`: This will be something like
    `https://github.com/GoogleCloudPlatform/forseti-security/archive/{TAG_NAME}.tar.gz`.
    You can find the tag names from [this page](https://github.com/GoogleCloudPlatform/forseti-security/tags);
    the tag name starts with "v". If you want to use master branch,
    then set "TAG_NAME" to "master".
  * `release-version`: Either "master" or the tag name, without the "v",
    e.g. for the release with tag name "v1.0", the `release-version` will be "1.0". (The quotes are required in the yaml.)

  Example:

  ```yaml
      # master release:
      release-version: "master"
      src-path: https://github.com/GoogleCloudPlatform/forseti-security/archive/master.tar.gz

      # v1.0 release:
      release-version: "1.0"
      src-path: https://github.com/GoogleCloudPlatform/forseti-security/archive/v1.0.tar.gz
  ```
There are other templates that you can modify:

* `py/inventory/cloudsql-instance.py`:  The template for the
  Google Cloud SQL instance.
* `py/inventory/cloudsql-database.py`: The template for the
  Google Cloud SQL database.
* `py/storage/bucket.py`: The template for the
  Google Cloud Storage buckets.
* `py/forseti-instance.py`: The template for the
  Compute Engine instance where Forseti Security will run.
   * You can customize the startup script (more about
     [startup scripts in GCP docs](https://cloud.google.com/deployment-manager/docs/step-by-step-guide/setting-metadata-and-startup-scripts)).
   * By default, the startup script will setup the
     environment to install the Forseti Security and run the tools every hour.

### Enabling GSuite Google Groups collection
To enable the collection of GSuite Google Groups collection for processing by
`scanner` and `enforcer` first make sure you've completed the prerequisite steps
of [creating a service
account](/docs/common/SERVICE-ACCOUNT.md#create-a-service-account-for-inventorying-of-gsuite-google-groups) just for this functionality.

Once completed you can update the following variables in your version of the
`deploy-forseti.yaml`

* **inventory-groups**: Set this to `true` to enable collection.
* EMAIL\_ADDRESS\_OF\_A\_GSUITE\_SUPER\_ADMIN: Use of the Admin API requires
  delegation (impersonation). Enter an email address of a super-admin in the
  GSuite account.
* EMAIL\_ADDRESS\_OF\_YOUR\_GROUPS\_SERVICE\_ACCOUNT: This is the email address
  of the service account you created just for inventorying GSuite Google Groups.
* **groups-service-account-key-file**: This file tells the `inventory` tool
  where to look for the key file. This shouldn't be changed unless you have also
  changed the flag in `deployment-templates/py/forseti-instance.py`.

## Customize rules.yaml
By default, the DM template has a rules.yaml that will allow service accounts on
the organization and its children (e.g. projects) IAM policies. For more
information, refer to the [rules schema](scanner/rules.md)
as well as the [scanner unit tests](/tests/scanner) for examples and explanations.

Once you finish customizing rules.yaml, upload it to your SCANNER\_BUCKET.
The `py/forseti_instance.py` template looks for the rules.yaml
in gs://SCANNER\_BUCKET/rules, so if you have a different location
for your rules.yaml, be sure to update the template
accordingly (e.g. replace every instance of "rules/rules.yaml"
with the appropriate path so the scanner knows where to find it).

## Deploy Forseti Security
After you configure the deployment template variables you can create a new deployment.

### Deploy without GSuite Google Groups collection enabled
```sh
$ gcloud deployment-manager deployments create forseti-security \
  --config path/to/deploy-forseti.yaml
```

### Deploy with GSuite Google Groups collection enabled
```sh
$ gcloud deployment-manager deployments create forseti-security \
  --config path/to/deploy-forseti.yaml
```

```sh
$ gcloud compute copy-files <downloaded_key> \
      forseti-security:/home/ubuntu/forseti-security/service-account-key.json \
      --zone <your zone, default is us-central1>
```

You can view the details of your deployment in the
Cloud Console [Deployment Manager dashboard](https://console.cloud.google.com/deployments).
Also, if you're using the default startup script, Forseti Security
should run on the top of the hour, drop a
csv in `gs://SCANNER_BUCKET/scanner_violations/`,
and email you the inventory and scanner results.

## Making changes to your deployment
If you need to make changes to your deployment,
refer to the [documentation](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments)
for more details.

Most of the changes you will probably make will be around the
deployment properties, such as the `src-path` (e.g. you want your deployment
to run a certain version of Forseti Security), notification email
addresses, or the instance type. There are a few steps involved to update
your deployment:

1. Edit the deploy-forseti.yaml.
2. Run the update command:

  ```sh
  $ gcloud deployment-manager deployments update forseti-security \
    --config path/to/deploy-forseti.yaml
  ```

3. If you made changes that affect the GCE instance's startup script
  (e.g. changing the properties of the "Compute Engine" section in
  deploy-forseti.yaml or the actual startup script in py/forseti-instance.py),
  you may need to reset the instance to see the changes take effect:

  ```sh
  $ gcloud compute instances reset <GCE instance name>
  ```

## Troubleshooting
* **Getting errors about invalid resources?**
  Check that your bucket or Cloud SQL instance names are unique.
* **Getting errors about `MANIFEST_EXPANSION_USER_ERROR`?**
  The syntax in your template might be invalid. Refer to the error message
  for the line number and erroneous template.
* **Need to delete your deployment and try again?**
  Before you do so, make sure to rename your Cloud SQL instance
  (INSTANCE\_NAME) in the template to something new before creating a new deployment.
