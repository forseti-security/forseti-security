# Deploying Forseti Security to Google Cloud

One of the goals of Forseti Security is to provide continuous scanning and enforcement in your GCP environment. [Deployment Manager](https://cloud.google.com/deployment-manager/docs/) is a Google Cloud service that helps you automate the deployment and management of your GCP resources. We are using DM to do the following:

* Create a CloudSql instance and database for storing Forseti Inventory data.
* Create a GCE instance for deploying Forseti Security.
* Manage configuration for Forseti Security and automatically run the tools.

We are also working on a way to deploy Forseti Security to GKE.

# Getting started

### Prerequisites
* Install and update `gcloud`. Check in the output of `gcloud info` whether your `gcloud` environment is using the right project and username; if not, login and init your environment.

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

### A note about Deployment Templates
The provided Deployment Templates are samples for you to use -- you may need to change them according to the needs of your deployment environment.

### Setting up your Cloud SQL instance.
* Create a new deployment for Cloud SQL. The deployment templates use the deployment name (e.g. `forseti-cloudsql-170224`) as the Cloud SQL instance name. As noted, you might also want to change the `region` property.  
**NOTE**: If you delete your deployment (including the Cloud SQL instance) and re-create it, you must choose a new name, otherwise you'll get an error that the instance still exists. (The instance name cannot be reused for about 7 days.)

```sh
$ gcloud deployment-manager deployments create forseti-cloudsql-170224 --config forseti-cloudsql.yaml
```

* The deployment may fail with a 403 error, "Operation failed because another operation was already in progress". ([Github issue](https://github.com/GoogleCloudPlatform/forseti-security/issues/11)). If you get that error, update the deployment:

```sh
$ gcloud deployment-manager deployments update forseti-cloudsql-170224 --config forseti-cloudsql.yaml
```

* You should see the following output upon successful deployment:

```
NAME                TYPE                       STATE      ERRORS  INTENT
inventory-database  sqladmin.v1beta4.database  COMPLETED  []  
inventory-instance  sqladmin.v1beta4.instance  COMPLETED  []  
```

* Setup your Cloud SQL user, either by setting up the [default user's password](https://cloud.google.com/sql/docs/mysql/create-manage-users#user-root) or by creating a new Cloud SQL user.  
To create a new Cloud SQL user, either use the [Cloud console](https://cloud.google.com/sql/docs/mysql/create-manage-users#creating) or the following `gcloud` command. (In the below example, the user's name is `forseti-user`.)

```sh
$ gcloud beta sql users set-password forseti-user [HOST] \
   --instance=forseti-cloudsql-170224 --password=f0rs3t1Secur1ty
```

From the [docs](https://cloud.google.com/sql/docs/mysql/create-manage-users#creating): "Users created using Cloud SQL will have all privileges except FILE and SUPER."

### Setting up Cloud Storage buckets
Next, set up your Cloud Storage buckets. These are used by the Forseti Security tools to store data, such as configurations, rule definitions, and tool output.

* Create a copy of the sample config (forseti-storage.yaml.sample) and rename it (e.g. `forseti-storage.yaml`).

* Edit the config file and change the bucket names accordingly.

  * There are restrictions on bucket names (e.g. they must be unique). Refer to the [bucket naming guidelines](https://cloud.google.com/storage/docs/naming) for more information.
  * You may opt to create more buckets than just the 2 in the sample. For example, you might want to store the output from the Forseti Scanner in one bucket and rule definitions in another.

* Deploy the buckets.

### Setting up Forseti Security
Now that you've set up your Cloud SQL instance, you can deploy Forseti Security in Compute Engine.

* Create a copy of the sample config (forseti-gce.yaml.sample) and rename it (e.g. `forseti-gce.yaml`).

* Edit the config file and change the value for `YOUR_SERVICE_ACCOUNT` to a service account that you will use to access the Cloud APIs (Cloud Storage, Resource Manager, etc.). For now, you can probably use the default application credentials (`PROJECTNUMBER-compute@developer.gserviceaccount.com`).

* Create a new deployment for the GCE instance.

```sh
$ gcloud deployment-manager deployments create forseti-gce-170224 --config forseti-gce.yaml
```

* If you make any changes to the deployment template, then update your deployment and reset the VM:

```sh
$ gcloud deployment-manager deployments update forseti-gce-170224 --config forseti-gce.yaml
$ gcloud compute instances reset forseti-gce-170224
```
