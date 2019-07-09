---
title: Manual
order: 003
---

# {{ page.title }}

This page describes the steps to install and deploy Forseti manually on
Google Cloud Platform (GCP). It's best to use the
[automated installer]({% link _docs/v2.18/setup/install.md %})
for an easy and error-free deployment. Use this guide only if you strongly
prefer to install Forseti yourself, or if you want to learn about the
installation process.

To complete this guide, you will need in-depth knowledge of GCP. For example,
you will need to know how to use the gcloud command-line tool and where to bind
a service account to a VM in the GCP Console. This guide refers to the installer
and deployment templates for specific details of the commands to use.

---

## Create a project

Create a new project to host Forseti. Forseti is intended to run in its own dedicated project to
control access to its highly privileged permissions. Assign a billing account to the project.

### Enable APIs

Install the required APIs for Forseti Security using the following command:

```bash
gcloud services enable <API URI>
```

{% include docs/v2.18/required-apis.md %}

## Deploy a server VM

### Create a Forseti server service sccount

Create a server service account by running the following command:

```bash
gcloud iam service-accounts create forseti-server-gcp-####### --display-name forseti-server-gcp-#######
```

Where `#######` is a random alphanumeric unique identifier.

### Assign roles

For information about the roles you need to assign to the Forseti server
service account, see
[the server service account]({% link _docs/v2.18/concepts/service-accounts.md %}#the-server-service-account).

### Create a Forseti server VM instance

* For information about the specifications needed for a Forseti server
  VM instance, see the
  [Compute Engine deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/deployment-templates/compute-engine/server/forseti-instance-server.py)
* When you create the instance, set the service account of the instance to the service account you just created.
    * If you already have an instance you want to use, follow the process to
    [update the service account](https://cloud.google.com/compute/docs/access/create-enable-service-accounts-for-instances#changeserviceaccountandscopes).

### Install the Forseti Server

To install the Forseti Server, follow the steps below:

1. SSH into the server VM:

    ```bash
    gcloud compute --project <YOUR_PROJECT> ssh --zone <YOUR_ZONE> <YOUR_FORSETI_SERVER_NAME>
    ```

1. To become an Ubuntu user, run the following command:

    ```bash
    sudo su ubuntu
    ```

1. `git clone` from the [forseti repo](https://github.com/GoogleCloudPlatform/forseti-security),
and check out the [latest release](https://github.com/GoogleCloudPlatform/forseti-security/releases)
by their tags:

    ```bash
    git clone https://github.com/GoogleCloudPlatform/forseti-security.git

    git checkout tags/v<version_number>
    ```

1. To install Forseti server and necessary components like Fluentd
and Cloud SQL Proxy, follow the setup instructions in the
[startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/deployment-templates/compute-engine/server/forseti-instance-server.py#L109).

1. Create the following firewall rules:

    ```bash
    # To create firewall rules, you will need the email address of your service account.
    # You can get the service account's email address by running command
    # gcloud iam service-accounts list
    # The email address will be in this format: forseti-server-gcp-#######@PROJECT-ID.iam.gserviceaccount.com

    # Create a firewall rule to block out all the ingress traffic.
    gcloud compute firewall-rules create forseti-server-deny-all --action DENY --target-service-accounts <SERVICE_ACCOUNT_EMAIL_ADDRESS> --priority 1 --direction INGRESS --rules icmp,udp,tcp

    # Create a firewall rule to open only port tcp:50051 within the internal network (ip-ranges - 10.128.0.0/9).
    gcloud compute firewall-rules create forseti-server-allow-grpc --action ALLOW --target-service-accounts <SERVICE_ACCOUNT_EMAIL_ADDRESS> --priority 0 --direction INGRESS --rules tcp:50051 --source-ranges 10.128.0.0/9

    # Create a firewall rule to open only port tcp:22 (ssh) to all the external traffics from the internet.
    gcloud compute firewall-rules create forseti-server-allow-ssh-external --action ALLOW --target-service-accounts <SERVICE_ACCOUNT_EMAIL_ADDRESS> --priority 0 --direction INGRESS --rules tcp:22 --source-ranges 0.0.0.0/0
    ```

### Configuration

Forseti server configuration and rule files are configured and stored in
Cloud Storage. For more information, see
[Configuring Forseti]({% link _docs/v2.18/configure/general/index.md %}).

### G Suite Integration

To integrate G Suite, you'll need to enable domain-wide delegation in G Suite.
For more information, see how to
[enable G Suite access]({% link _docs/v2.18/configure/inventory/gsuite.md %})

## Create a Database

### Create a Cloud SQL instance.

To create a Cloud SQL instance, see
[Creating Instances](https://cloud.google.com/sql/docs/mysql/create-instance).

For more information about the specifications needed for the Cloud SQL instance,
see the [Cloud SQL template](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/deployment-templates/cloudsql/cloudsql-instance.py).

## Deploy a client VM

### Create a Forseti client service account

Create a client service account by running the following command:

```bash
gcloud iam service-accounts create forseti-client-gcp-####### --display-name forseti-client-gcp-#######
```

Where `#######` is a random alphanumeric unique identifier.

### Assign roles

For information about the roles you need to assign to the Forseti server
service account, see
[the client service account]({% link _docs/v2.18/concepts/service-accounts.md %}#the-client-service-account).

### Create a Forseti client VM Instance

* For information about the specifications needed for a Forseti server
  VM instance, see the
  [Compute Engine deployment template](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/deployment-templates/compute-engine/server/forseti-instance-server.py).
* When you create the instance, bind the server service account to the VM instance.
* [Enable Compute Engine OS Login](https://cloud.google.com/compute/docs/instances/managing-instance-access#enable_oslogin).

### Install the Forseti client

To install the Forseti client, follow the steps below:

1. SSH into the client VM:

    ```bash
    gcloud compute --project <YOUR_PROJECT> ssh --zone <YOUR_ZONE> <YOUR_FORSETI_CLIENT_NAME>
    ```

1. Run the following command to become an Ubuntu user:

    ```bash
    sudo su ubuntu
    ```

1. `git clone` from the [Forseti repo](https://github.com/GoogleCloudPlatform/forseti-security),
and check out the [latest release](https://github.com/GoogleCloudPlatform/forseti-security/releases)
by their tags:

    ```bash
    git clone https://github.com/GoogleCloudPlatform/forseti-security.git

    git checkout tags/v<version_number>
    ```

1. To install the Foresti command-line interface (CLI), follow the setup
instructions in the
[startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/deployment-templates/compute-engine/client/forseti-instance-client.py#L93).

### Configuration

Forseti client configuration files are configured and stored in
Cloud Storage. For more information, see
[Configuring Forseti]({% link _docs/v2.18/configure/general/index.md %}).

## What's next

* Learn how to [use Forseti]({% link _docs/v2.18/configure/inventory/index.md %}).
