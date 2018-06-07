---
title: Manual Deployment
order: 004
---

# {{ page.title }}

This page describes the steps to install and deploy Forseti manually on 
Google Cloud Platform (GCP). It's best to use the
[automated installer]({% link _docs/latest/setup/install.md %})
for an easy and error-free deployment. Use this guide only if you strongly
prefer to install Forseti yourself, or if you want to learn about the
installation process.

To complete this guide, you will need in-depth knowledge of GCP. For example,
you will need to know how to use the gcloud command-line tool and where to bind
a service account to a VM in the GCP Console. This guide refers to the installer
and deployment templates for specific details of the commands to use.

## Create a project

Create a new project to host Forseti.  Forseti is intended to run in its own
dedicated project so that access to its highly privileged permissions can be
controlled.  Assign a billing account to the project.

### Enable APIs

For information about the APIs you need to enable in the project that hosts
Forseti, see [required APIs]({% link _docs/latest/required_apis.md %}).

## Deploy a server VM

### Create a Forseti server service sccount

Create a server service account by running the following command:

```
forseti-server-gcp-#######@fooproject.iam.gserviceaccount.com
```

Where `#######` is a random alphanumeric unique identifier that must be
accepted when used for the Cloud Storage bucket name.

### Assign roles

For information about the roles you need to assign to the Forseti server
service account, see 
[the server service account]({% link _docs/latest/concepts/service-accounts.html#the-server-service-account %}).

### Create a Forseti server VM instance

* For information about the specifications needed for a Forseti server
  VM instance, see the [Compute Engine deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)
* When you create the instance, bind the server service account to the VM instance

### Install the Forseti Server

To install the Forseti Server, follow the steps below:

1. SSH into the server VM
1. Run the following command to become an Ubuntu user:

        sudo su ubuntu
        
1. `git clone` from the [forseti repo](https://github.com/GoogleCloudPlatform/forseti-security), and check out the [latest release](https://github.com/GoogleCloudPlatform/forseti-security/releases) by their tags.
        
        git clone https://github.com/GoogleCloudPlatform/forseti-security.git
        git checkout tags/<tag_number>
        
1. Run the steps in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)
1. Create [firewall rules](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/gcp/installer/forseti_server_installer.py)

### Configuration

Forseti server configuration and rule files are configured and stored in
Cloud Storage. For more information, see
[Configuring Forseti]({% link _docs/latest/howto/configure/configuring-forseti.md %}).

### G Suite Integration

To integrate G Suite, you'll need to enable domain-wide delegation in G Suite.
For more information, see [Enabling G Suite Google Groups Collection](https://forsetisecurity.org/docs/howto/configure/gsuite-group-collection.html)

## Create a Database

### Create a Cloud SQL instance.

To create a For information about the specifications needed for a Cloud
SQL instance, see the [Cloud SQL template](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/cloudsql/cloudsql-instance.py).

## Deploy a client VM

### Create a Forseti client service account

Create a client service account by running the following command:

```
forseti-client-gcp-#######@fooproject.iam.gserviceaccount.com
```

Where `#######` is a random alphanumeric unique identifier that must be
accepted when used for the Cloud Storage bucket name.

### Assign roles

For information about the roles you need to assign to the Forseti server
service account, see
[the client service account]({% link _docs/latest/concepts/service-accounts.html#the-client-service-account %}).

### Create a Forseti client VM Instance

* For information about the specifications needed for a Forseti server
  VM instance, see the [Compute Engine deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)
* When you create the instance, bind the server service account to the VM instance
* [Enable computeOS login](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/gcp/installer/util/gcloud.py)

### Install the Forseti client

To install the Forseti client, follow the steps below:

1. SSH into the client VM
1. Run the following command to become an Ubuntu user:

        sudo su ubuntu
        
1. `git clone` from the [forseti repo](https://github.com/GoogleCloudPlatform/forseti-security), and check out the [latest release](https://github.com/GoogleCloudPlatform/forseti-security/releases) by their tags.

        git clone https://github.com/GoogleCloudPlatform/forseti-security.git
        git checkout tags/<tag_number>
        
1. Run the steps in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)

### Configuration

Forseti client configuration files are configured and stored in
Cloud Storage. For more information, see
[Configuring Forseti]({% link _docs/latest/howto/configure/configuring-forseti.md %}).

## What's next

  - Learn how to [use Forseti]({% link _docs/latest/configure/inventory/index.md %}).
