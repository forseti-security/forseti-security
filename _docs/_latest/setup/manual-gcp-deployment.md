It is highly recommended that you use the [automated installer](({% link _docs/latest/setup/install.md %})
for an easy and error-free deployment.

But in case you prefer to install and deploy Forseti on your own, or just
curious what goes into the installation process, you can follow the steps below.

These steps assume you have certain level of GCP knowledge (how to use gcloud,
where to bind the service account to the VM in the Cloud Console, etc),
and will by necessity point to the installer and Deployment Templates for
specific details of the commands to use.

# Create Project

## Create a new project to host Forseti.

## Assign a billing account.

## Enable the following APIs in the projects:

See [this doc]({% link _docs/latest/required_apis.md %})
to see the APIs that need to be enabled in the project hosting Forseti.

# Deploy Server VM

## Create a Forseti server service account.
```
forseti-server-gcp-#######@fooproject.iam.gserviceaccount.com
```

Where `#######` is a random alphanumeric unique identifier that must be
accepted when used for GCS bucket name.

## Assign roles:

See [this doc]({% link _docs/latest/howto/configure/configuring-forseti.md %})
to see the roles need to be assigned to the Forseti server service account.

## Create a Forseti [server VM instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py)
* n1-standard-2
* ubuntu-1804-lts
* bind the server service account to the VM instance

## Install Forseti Server
* ssh into the server VM
* become ubuntu user
* git clone the latest release from the stable branch
* run the steps in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/server/forseti-instance-server.py#L114)
* create [firewall rules](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/gcp/installer/forseti_server_installer.py#L164)

## Configuration
* [Forseti server conf](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/configs/server/forseti_conf_server.yaml.in)

Make a copy of `forseti_conf_server.yaml.in` and call it `forseti_conf_server.yaml`
Fill-in the placeholder values as denoted by `{FOOBAR_PLACEHOLDER}`
Save it to `/home/ubuntu/forseti-security/configs`

* [scanner rule files](https://github.com/GoogleCloudPlatform/forseti-security/tree/stable/rules)
Fill-in the placeholder values as denoted by `{FOOBAR_PLACEHOLDER}`

* Copy the Forseti server configuration file to:
```
gs://forseti-server-#######/configs/forseti_conf_server.yaml
 ```
* Copy the default Forseti rules to:
```
gs://forseti-server-#######/rules
```

# Create Database

## Create a [CloudSQL instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/cloudsql/cloudsql-instance.py)
	* forseti-server-db-#######
	* MySQL 5.7
	* second generation
	* vCPUs: 1
	* Memory: 3.75 GB
	* SSD storage: 25 GB
	* db-n1-standard-1

# Deploy Client VM

## Create a Forseti client service account.
```
forseti-client-gcp-#######@fooproject.iam.gserviceaccount.com
```

## Assign roles:
	* roles/storage.objectViewer
	* roles/logging.logWriter

## Create a forseti [client VM instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/client/forseti-instance-client.py).
* n1-standard-2
* ubuntu-1804-lts
* bind the client service account to the VM instance
* [enable computeOS login](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/install/gcp/installer/util/gcloud.py#L709)

## Install Forseti Client
* ssh into the client VM
* become ubuntu user
* git clone the latest release from the stable branch
* run the steps in the [startup-script](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/deployment-templates/compute-engine/client/forseti-instance-client.py)

## Configuration
* [Forseti client conf](https://github.com/GoogleCloudPlatform/forseti-security/blob/stable/configs/server/forseti_conf_client.yaml.in)

Make a copy of `forseti_conf_client.yaml.in` and call it `forseti_conf_client.yaml`
Fill-in the placeholder values as denoted by `{FOOBAR_PLACEHOLDER}`
This file does not need to be saved locally.  It will always be read from the GCS bucket
on installation.

* Copy the Forseti client configuration file to:
 ```
 gs://forseti-client-#######/configs/forseti_conf_client.yaml
 ```

GSuite Integration
* [Enable DwD for the server service account](https://forsetisecurity.org/docs/howto/configure/gsuite-group-collection.html)
