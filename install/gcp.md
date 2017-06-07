---
install_type: 'gcp'
permalink: /install/gcp/
---
# Google Cloud Platform installation

One of the goals of Forseti Security is to provide continuous scanning
and enforcement in your Google Cloud Platform (GCP) environment.
[Deployment Manager](https://cloud.google.com/deployment-manager/docs/) (DM)
is a Google Cloud service that helps you automate the deployment and
management of your GCP resources. We are using DM to do the following:

* Create a Cloud SQL instance and database for storing inventory data.
* Create a Cloud Storage bucket for scanner output.
* Create a Google Compute Engine (GCE) instance for deploying and running
Forseti Security.
* Manage configuration for Forseti Security and automatically run
  the **inventory** and **scanner** modules.

**Note**: The DM templates currently do not schedule or execute the **enforcer**
module.

## Prerequisites
{% include install_prerequisites.md %}

## Customize Deployment Templates
The provided DM templates are samples for you to use. Make a copy of
`deploy-forseti.yaml.sample` (found in samples/deployment-manager) as `deploy-forseti.yaml` and update the following variables:

* **CLOUDSQL\_INSTANCE\_NAME**
  * Instance name must start with a letter and consist of lowercase letters,
    numbers, and hyphens (e.g. "valid-instancename-1",
    NOT "1\_invalid\_instanceName.com"). See [naming guidelines](https://cloud.google.com/sql/docs/mysql/instance-settings#settings-2ndgen)
    for more information.
  * Instance name must also be unique. If you delete a Cloud SQL instance
    (either by deleting your deployment or manually through
    gcloud or the Cloud Console), you cannot reuse that instance name
    for up to 7 days.
* **SCANNER\_BUCKET**
  * This is just the bucket name; do not include "gs://".
  * The bucket name is subject to the [bucket naming guidelines](https://cloud.google.com/storage/docs/naming).
  * _Note_: use the same SCANNER\_BUCKET name for both the "Cloud Storage" and
    "Compute Engine" sections in the template.
* **GCP\_SERVICE\_ACCOUNT**
  * This is the service account you created for reading GCP resource data.
* ORGANIZATION\_ID\_NUMBER (the organization id number; get it from the Organization
  IAM settings or ask your Organization Administrator)
* **SENDGRID\_API\_KEY** (the API key for SendGrid email service)
* **NOTIFICATION\_SENDER\_EMAIL** (email address of notifications sender)
* **NOTIFICATION\_RECIPIENT\_EMAIL** (email address of notifications recipient)
* **src-path** and **release-version**: The default is to retrieve the
  latest stable release (currently hardcoded) from the GoogleCloudPlatform
  Forseti repo.
  * `src-path`: This must be the git repo, without the ".git" extension.
    You probably only need to change this if you are pulling from a different
    fork than GoogleCloudPlatform.
  * `release-version`: Either "master" or the tag name, without the "v",
    e.g. for the release with tag name "v1.0", the `release-version` will be
    "1.0". (The quotes are required in the yaml.)

  Example:

  ```yaml
      # master branch:
      branch-name: "master"
      # release-version: "1.0"
      src-path: https://github.com/GoogleCloudPlatform/forseti-security

      # v1.0 release:
      # branch-name: "master"
      release-version: "1.0"
      src-path: https://github.com/GoogleCloudPlatform/forseti-security
  ```

There are other templates that you can modify:

* `inventory/cloudsql-instance.py`:  The template for the
  Google Cloud SQL instance.
* `inventory/cloudsql-database.py`: The template for the
  Google Cloud SQL database.
* `storage/bucket.py`: The template for the
  Google Cloud Storage buckets.
* `forseti-instance.py`: The template for the
  Compute Engine instance where Forseti Security will run.
   * You can customize the startup script (more about
     [startup scripts in GCP docs](https://cloud.google.com/deployment-manager/docs/step-by-step-guide/setting-metadata-and-startup-scripts)).
   * By default, the startup script will setup the
     environment to install the Forseti Security and run the tools every hour.

### Enabling GSuite Google Groups collection
To enable the collection of GSuite Google Groups collection for processing by
`scanner` and `enforcer` first make sure you've completed the prerequisite steps
of [creating a service account]({{ site.baseurl }}{% link common/service_accounts.md %})
just for this functionality.

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
information, refer to the [rules schema]({{ site.baseurl }}{% link modules/core/scanner/rules.md %})
for more details.

Once you finish customizing rules.yaml, upload it to your SCANNER\_BUCKET.
The `py/forseti_instance.py` template looks for the rules.yaml
in gs://SCANNER\_BUCKET/rules, so if you have a different location
for your rules.yaml, be sure to update the template accordingly
(e.g. replace every instance of "rules/rules.yaml"
with the appropriate path so the scanner knows where to find it).

## Deploy Forseti Security
After you configure the deployment template variables, create a new deployment.

```sh
$ gcloud deployment-manager deployments create forseti-security \
  --config path/to/deploy-forseti.yaml
```

You can view the details of your deployment in the Cloud Console
[Deployment Manager dashboard](https://console.cloud.google.com/deployments).
Also, if you're using the default startup script, Forseti Security
should run on the top of the hour, drop a
csv in `gs://SCANNER_BUCKET/scanner_violations/`, and email you the inventory
and scanner results.

### Deploy with GSuite Google Groups collection enabled
Create your deployment first, then run these commands:

```sh
$ gcloud compute copy-files <path_to_downloaded_key> \
    <your_user>@<your_instance_name>:/tmp/service-account-key.json
    
$ gcloud compute ssh <your_user>@<your_instance_name>

$ <your_instance>: sudo mv /tmp/service-account-key.json <the_path_you_specified_in_deploy_forseti.yaml>
```

**Note**: The remote destination path of where you put the key on the vm
instance should match what you specified in your deployment YAML for
`groups-service-account-key-file:`.

## Making changes to your deployment
If you need to make changes to your deployment, refer to the
[documentation](https://cloud.google.com/deployment-manager/docs/deployments/updating-deployments)
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
* **Getting errors about `MANIFEST\_EXPANSION\_USER_ERROR`?**
  The syntax in your template might be invalid. Refer to the error message
  for the line number and erroneous template.
* **Need to delete your deployment and try again?**
  Before you do so, make sure to rename your Cloud SQL instance
  (INSTANCE\_NAME) in the template to something new before creating a new
  deployment.
