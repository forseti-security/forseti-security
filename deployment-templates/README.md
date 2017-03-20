# Deploying Forseti Security to Google Cloud

* [Prerequisites](#prerequisites)
* [Set up a service account](#set-up-a-service-account)
* [Customize Deployment Templates](#customize-deployment-templates)
* [Customze rules.yaml](#customize-rulesyaml)
* [Deploy Forseti Security](#deploy-forseti-security)
* [Troubleshooting](#troubleshooting)

One of the goals of Forseti Security is to provide continuous scanning and enforcement in your Google Cloud Platform (GCP) environment. [Deployment Manager](https://cloud.google.com/deployment-manager/docs/) (DM) is a Google Cloud service that helps you automate the deployment and management of your GCP resources. We are using DM to do the following:

* Create a Cloud SQL instance and database for storing inventory data.
* Create a Cloud Storage bucket for scanner output.
* Create a Google Compute Engine (GCE) instance for deploying and running Forseti Security.
* Manage configuration for Forseti Security and automatically run the [inventory](../google/cloud/security/inventory/README.md) and [scanner](../google/cloud/security/scanner/README.md) modules.

**Note**: The DM templates currently do not schedule or execute the [enforcer](../google/cloud/security/enforcer/README.md) module.

## Prerequisites
* Install and update `gcloud`. Verify whether the output of `gcloud info` shows the right project and account. If not, login and init your environment (see following steps).

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

* Create a new project in your Cloud Console.
  * You can also re-use a project that is dedicated for Forseti Security.
  * Enable Billing in your project, if you haven't already.

* Initialize your `gcloud` commandline environment to select your project and auth your Google Cloud account.

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

* Enable **Deployment Manager API**.

  ```sh
  $ gcloud beta service-management enable deploymentmanager.googleapis.com
  ```

## Set up a service account
In order to run Forseti Security, you must add a service account to your **organization-level** IAM policy with at least the `Browser` role. This allows Forseti Security to perform operations such as listing the projects within your organization.

**Note**: If you also want to audit/enforce organization IAM policies, you'll need to assign the `Organization Administrator` role. Note that this is a very powerful role; if your GCE instance gets compromised, your entire account could also be compromised!

```sh
$ gcloud organizations add-iam-policy-binding ORGANIZATION_ID \
  --member=serviceAccount:YOUR_SERVICE_ACCOUNT \
  --role=roles/browser
```

## Customize Deployment Templates
The provided DM templates are samples for you to use. Make a copy of `deploy-forseti.yaml.sample` as `deploy-forseti.yaml` and update the following variables:

* CLOUDSQL\_INSTANCE\_NAME
  * Instance name must start with a letter and consist of lowercase letters, numbers, and hyphens (e.g. "valid-instancename-1", NOT "1\_invalid\_instanceName.com"). See [naming guidelines](https://cloud.google.com/sql/docs/mysql/instance-settings#settings-2ndgen) for more information.
  * Instance name must also be unique. If you delete a Cloud SQL instance (either by deleting your deployment or manually through gcloud or the Cloud Console), you cannot reuse that instance name for up to 7 days.
* SCANNER\_BUCKET
  * This is just the bucket name; do not include "gs://".
  * The bucket name is subject to the [bucket naming guidelines](https://cloud.google.com/storage/docs/naming).
  * **Note**: use the same SCANNER\_BUCKET name for both the "Cloud Storage" and "Compute Engine" sections in the template.
* YOUR\_SERVICE\_ACCOUNT
  * This can be the application default service account, i.e. `PROJECTNUMBER-compute@developer.gserviceaccount.com`.
  * You must assign the `Browser` role to this service account on the **organization-level** IAM policy.
* YOUR\_ORG\_ID (the organization id number; get it from the Organization IAM settings or ask your Organization Administrator)
* YOUR\_SENDGRID\_API\_KEY (the API key for SendGrid email service)
* EMAIL\_ADDRESS\_OF_YOUR\_SENDER (email address of your email sender)
* EMAIL\_ADDRESS\_OF\_YOUR\_RECIPIENT (email address of your email recipient)
* `src-path` and `release-version`: The default is to retrieve the "master" branch. If you want to get a release archive, e.g. v1.0, change the following:
  * `src-path`: https://github.com/GoogleCloudPlatform/forseti-security/archive/{TAG_NAME}.tar.gz (you can find them from [this page](https://github.com/GoogleCloudPlatform/forseti-security/tags); the tag name starts with "v").
  * `release-version`: Either "master" or the tag name, without the "v", e.g. "1.0". (The quotes are required in the yaml.)

There are other templates that you can modify:

* `py/inventory/cloudsql-instance.py`:  The template for the Google Cloud SQL instance.
* `py/inventory/cloudsql-database.py`: The template for the Google Cloud SQL database.
* `py/storage/bucket.py`: The template for the Google Cloud Storage buckets.
* `py/forseti-instance.py`: The template for the Compute Engine instance where Forseti Security will run.
   * You can customize the startup script (more about [startup scripts in GCP docs](https://cloud.google.com/deployment-manager/docs/step-by-step-guide/setting-metadata-and-startup-scripts)).
   * By default, the startup script will setup the environment to install the Forseti Security and run the tools every hour.

## Customize rules.yaml
By default, the DM template has a rules.yaml that will allow service accounts on the organization and its children (e.g. projects) IAM policies. For more information, refer to the [rules schema](/google/cloud/security/scanner/samples/rules.md) as well as the [scanner unit tests](/tests/scanner) for examples and explanations.

Once you finish customizing rules.yaml, upload it to your SCANNER\_BUCKET. The `py/forseti_instance.py` template looks for the rules.yaml in gs://SCANNER\_BUCKET/rules, so if you have a different location for your rules.yaml, be sure to update the template accordingly (e.g. replace every instance of "rules/rules.yaml" with the appropriate path so the scanner knows where to find it).

## Deploy Forseti Security
After you configure the deployment template variables you can create a new deployment.

```sh
$ gcloud deployment-manager deployments create forseti-security \
  --config path/to/deploy-forseti.yaml
```

You can view the details of your deployment in the Cloud Console [Deployment Manager dashboard](https://console.cloud.google.com/deployments). Also, if you're using the default startup script, Forseti Security should run on the top of the hour, drop a csv in `gs://SCANNER_BUCKET/scanner_violations/`, and email you the inventory and scanner results.

## Making changes to your deployment
If you need to make changes to your deployment, refer to the [documentation](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments) for more details.

Most of the changes you will probably make will be around the deployment properties, such as the `src-path` (e.g. you want your deployment to run a certain version of Forseti Security), notification email addresses, or the instance type. There are a few steps involved to update your deployment:

1. Edit the deploy-forseti.yaml.
2. Run the update command:

  ```sh
  $ gcloud deployment-manager deployments update forseti-security \
    --config path/to/deploy-forseti.yaml
  ```

3. If you made changes that affect the GCE instance's startup script (e.g. changing the properties of the "Compute Engine" section in deploy-forseti.yaml or the actual startup script in py/forseti-instance.py), you may need to reset the instance to see the changes take effect:

  ```sh
  $ gcloud compute instances reset <GCE instance name>
  ```

## Troubleshooting

* **Getting errors about invalid resources?**
  Check that your bucket or Cloud SQL instance names are unique.
* **Getting errors about `MANIFEST_EXPANSION_USER_ERROR`?**
  The syntax in your template might be invalid. Refer to the error message for the line number and erroneous template.
* **Need to delete your deployment and try again?**
  Before you do so, make sure to rename your Cloud SQL instance (INSTANCE\_NAME) in the template to something new before creating a new deployment.
