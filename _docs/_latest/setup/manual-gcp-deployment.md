---
title: Manual Deployment on GCP
order: 004
---

# {{ page.title }}

It is highly recommended that you use the [automated installer](({% link _docs/latest/setup/install.md %})
for an easy and error-free deployment.

But in case you prefer to install and deploy Forseti on your own, or just
curious what goes into the installation process, you can follow the steps below.

These steps assume you have certain level of GCP knowledge (how to use gcloud,
where to bind the service account to the VM in the Cloud Console, etc),
and will by necessity point to the installer and Deployment Templates for
specific details of the commands to use.

## Create Project

Create a new project to host Forseti.  Forseti is intended to run in its own
dedicated project so that access to its highly privileged permissions can be
controlled.  Assign a billing account to the project.

### Enable APIs in Project

Reference [this doc]({% link _docs/latest/required_apis.md %})
to see the APIs that need to be enabled in the project hosting Forseti.

## Deploy Server VM

### Create a Forseti Server Service Account

```
forseti-server-gcp-#######@fooproject.iam.gserviceaccount.com
```

Where `#######` is a random alphanumeric unique identifier that must be
accepted when used for GCS bucket name.

### Assign Roles

Reference [this doc]({% link _docs/latest/concepts/service-accounts.html#the-server-service-account %})
to see the roles need to be assigned to the Forseti server service account.

### Create a Forseti Server VM Instance

* Reference [this deployment template for the specifications of the server VM instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py) to create.
* bind the server service account to the VM instance

### Install Forseti Server

* ssh into the server VM
* become ubuntu user
* git clone the latest release from the stable branch
* run the steps in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py#L114)
* create [firewall rules](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/gcp/installer/forseti_server_installer.py#L164)

### Configuration

Forseti server has configuration and rule files that needed to be configured
and stored in GCS. 
Reference [this doc]({% link _docs/latest/howto/configure/configuring-forseti.md %})
to see how.

### GSuite Integration

[Enable DwD for the server service account](https://forsetisecurity.org/docs/howto/configure/gsuite-group-collection.html)

## Create Database

### Create a CloudSQL instance.

Reference [this deployment template for the specifications of the CloudSQL instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/cloudsql/cloudsql-instance.py) to create.

## Deploy Client VM

### Create a Forseti client service account.

```
forseti-client-gcp-#######@fooproject.iam.gserviceaccount.com
```

### Assign Roles

Reference [this doc]({% link _docs/latest/concepts/service-accounts.html#the-client-service-account %})
to see the roles need to be assigned to the Forseti client service account.

### Create Forseti client VM Instance

* Reference [this deployment template for the specifications of the client VM instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/client/forseti-instance-client.py) to create.
* bind the client service account to the VM instance
* [enable computeOS login](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/gcp/installer/util/gcloud.py#L709)

### Install Forseti Client

* ssh into the client VM
* become ubuntu user
* git clone the latest release from the stable branch
* run the steps in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/client/forseti-instance-client.py)

### Configuration

Forseti client has configuration file that needed to be configured
and stored in GCS. 
Reference [this doc]({% link _docs/latest/howto/configure/configuring-forseti.md %})
to see how.

## What's next

  - How to [use Forseti]({% link _docs/latest/configure/inventory/index.md %}).
