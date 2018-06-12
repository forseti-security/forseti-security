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

---

## Create a project

Create a new project to host Forseti. Forseti is intended to run in its own
dedicated project so that access to its highly privileged permissions can be
controlled.  Assign a billing account to the project.

### Enable APIs

For information about the APIs you need to enable in the project that hosts
Forseti, see [required APIs]({% link _docs/latest/required_apis.md %}).

## Deploy a server VM

### Create a Forseti server service sccount

Create a server service account by running the following command:

```
gcloud iam service-accounts create forseti-server-gcp-####### --display-name forseti-server-gcp-#######
```

Where `#######` is a random alphanumeric unique identifier.

### Assign roles

For information about the roles you need to assign to the Forseti server
service account, see 
[the server service account]({% link _docs/latest/concepts/service-accounts.html#the-server-service-account %}).

### Create a Forseti server VM instance

* For information about the specifications needed for a Forseti server
  VM instance, see the [Compute Engine deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)
* When you create the instance, set the service account of the instance to the service account we just created or 
if you already created the instance, you can [update the service account](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#changeserviceaccountandscopes).

### Install the Forseti Server

To install the Forseti Server, follow the steps below:

1. SSH into the server VM
1. Run the following command to become an Ubuntu user:
    ```bash
    sudo su ubuntu
    ```
1. `git clone` from the [forseti repo](https://github.com/GoogleCloudPlatform/forseti-security), and check out the [latest release](https://github.com/GoogleCloudPlatform/forseti-security/releases) by their tags.
    ```bash
    git clone https://github.com/GoogleCloudPlatform/forseti-security.git
 
    git checkout tags/<tag_number>
    ``` 
1. Follow the setup instructions in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py#L109) 
to install Forseti server and all the necessary components like Fluentd and Cloud SQL Proxy.
1. Create firewall rules
    ```bash
    # Note: You will need the email address of your service account, you can get the email address by running command
    # gcloud iam service-accounts list
    # The email address will be in this format: forseti-server-gcp-#######@PROJECT-ID.iam.gserviceaccount.com
    
    # Create firewall rule to block out all the ingress traffic.
    gcloud compute firewall-rules create forseti-server-deny-all --action DENY --target-service-accounts <SERVICE_ACCOUNT_EMAIL_ADDRESS> --priority 1 --direction INGRESS --rules icmp,udp,tcp
    
    # Create firewall rule to open only port tcp:50051 within the internal network (ip-ranges - 10.128.0.0/9).
    gcloud compute firewall-rules create forseti-server-allow-grpc --action ALLOW --target-service-accounts <SERVICE_ACCOUNT_EMAIL_ADDRESS> --priority 0 --direction INGRESS --rules tcp:50051 --source-ranges 10.128.0.0/9
    
    # Create firewall rule to open only port tcp:22 (ssh) to all the external traffics from the internet.
    gcloud compute firewall-rules create forseti-server-allow-ssh-external --action ALLOW --target-service-accounts <SERVICE_ACCOUNT_EMAIL_ADDRESS> --priority 0 --direction INGRESS --rules tcp:22 --source-ranges 0.0.0.0/0
    ```

### Configuration

Forseti server configuration and rule files are configured and stored in
Cloud Storage. For more information, see
[Configuring Forseti]({% link _docs/latest/howto/configure/configuring-forseti.md %}).

### G Suite Integration

To integrate G Suite, you'll need to enable domain-wide delegation in G Suite.
For more information, see [Enabling G Suite Google Groups Collection]({% link _docs/latest/configure/gsuite.md %})

## Create a Database

### Create a Cloud SQL instance.

To create a For information about the specifications needed for a Cloud
SQL instance, see the [Cloud SQL template](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/cloudsql/cloudsql-instance.py).

## Deploy a client VM

### Create a Forseti client service account

Create a client service account by running the following command:

```
gcloud iam service-accounts create forseti-client-gcp-####### --display-name forseti-client-gcp-#######
```

Where `#######` is a random alphanumeric unique identifier.

### Assign roles

For information about the roles you need to assign to the Forseti server
service account, see
[the client service account]({% link _docs/latest/concepts/service-accounts.html#the-client-service-account %}).

### Create a Forseti client VM Instance

* For information about the specifications needed for a Forseti server
  VM instance, see the [Compute Engine deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)
* When you create the instance, bind the server service account to the VM instance
* [Enable computeOS login](https://cloud.google.com/compute/docs/instances/managing-instance-access#enable_oslogin)

### Install the Forseti client

To install the Forseti client, follow the steps below:

1. SSH into the client VM
    ```bash
    gcloud compute --project <YOUR_PROJECT> ssh --zone <YOUR_ZONE> <YOUR_FORSETI_CLIENT_NAME>
    ```
1. Run the following command to become an Ubuntu user:
    ```bash
    sudo su ubuntu
    ```
1. `git clone` from the [forseti repo](https://github.com/GoogleCloudPlatform/forseti-security), and check out the [latest release](https://github.com/GoogleCloudPlatform/forseti-security/releases) by their tags.
    ```bash
    git clone https://github.com/GoogleCloudPlatform/forseti-security.git
 
    git checkout tags/<tag_number>
    ```   
1. Follow the setup instructions in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/client/forseti-instance-client.py#L93) to install Forseti CLI.

### Configuration

Forseti client configuration files are configured and stored in
Cloud Storage. For more information, see
[Configuring Forseti]({% link _docs/latest/howto/configure/configuring-forseti.md %}).

## What's next

  - Learn how to [use Forseti]({% link _docs/latest/configure/inventory/index.md %}).
