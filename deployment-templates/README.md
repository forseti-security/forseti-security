# Deploying Forseti Security to Google Cloud

[Deployment Manager](https://cloud.google.com/deployment-manager/docs/) is a Google Cloud service that helps you automate the management of your GCP resources. We are using DM to do the following:

* Create a CloudSql instance and database for storing Forseti Inventory data.
* Create a GCE instance for deploying Forseti Security.
* Manage configuration for Forseti Security.

In the near future, we will also provide a way to deploy Forseti Security to GKE.

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

* Enable Cloud SQL API.

```sh
$ gcloud beta service-management enable sql-component.googleapis.com
```
* Enable Cloud SQL Admin API.

```sh
$ gcloud beta service-management enable sqladmin.googleapis.com
```
* Enable Cloud Resource Manager API.

```sh
$ gcloud beta service-management enable cloudresourcemanager.googleapis.com
```

### Setting up your Cloud SQL instance.
* Create a new deployment for Cloud SQL. The deployment templates use the deployment name (e.g. `forseti-cloudsql-170224`) as the Cloud SQL instance name.  
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

* Create the database user either through the [Cloud console](https://cloud.google.com/sql/docs/mysql/create-manage-users#changing_a_user_password) or with the following `gcloud` command. (The user's name is `forseti-user` for example.)

```sh
$ gcloud beta sql users set-password forseti-user [HOST] \
   --instance=forseti-cloudsql-170224 --password=f0rs3t1Secur1ty
```

### Setting up Forseti Security
Now that you've set up your Cloud SQL instance, you can deploy Forseti Security in Compute Engine.

* Create a new deployment for the GCE instance.

```sh
gcloud deployment-manager deployments create forseti-gce-170224 --config forseti-gce.yaml
```