It is highly recommended that you use the automated installer for an easy and robust deployment.

But in case you prefer to install and deploy Forseti on your own, you can follow the steps below.  These steps assume you have certain level of GCP knowledge (how to use gcloud, where to bind the service account to the VM in the Cloud Console, etc), and will by necessity point to the Deployment Templates for specific details commands that you will need to use.

# Create Project

## Create a new project to host forseti.

## Assign a billing account.

## Enable the following APIs in the projects:

	* Admin SDK API
	* AppEngine Admin API
	* BigQuery API
	* Cloud Billing API
	* Cloud Resource Manager API
	* Cloud SQL API
	* Cloud SQL Admin API
	* Compute Engine API
	* Deployment Manager API
	* IAM API

## Create a forseti server service account.
	* forseti-server-gcp-#######@fooproject.iam.gserviceaccount.com

## Assign roles:

	Org-Level
	* roles/iam.serviceAccountTokenCreator (gcloud)
	* roles/browser
	* roles/compute.networkViewer
	* roles/iam.securityReviewer
	* roles/appengine.appViewer
	* roles/bigquery.dataViewer
	* roles/servicemanagement.quotaViewer
	* roles/serviceusage.serviceUsageConsumer
	* roles/cloudsql.viewer
	* roles/compute.securityAdmin

	Project-Level
	* roles/storage.objectViewer
	* roles/storage.objectCreator
	* roles/cloudsql.client
	* roles/logging.logWriter

	Note: 
	`roles/iam.serviceAccountTokenCreator` can only be assigned by gcloud

## Create a forseti [server VM instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/deployment-templates/compute-engine/server/forseti-instance-server.py)
	* n1-standard-2
	* ubuntu-1804-lts
	* bind the server service account to the VM instance

## Install Forseti Server
	* ssh into the server VM
	* become ubuntu user
	* git clone the forseti release
	* run the steps in the startup-script
	* create [firewall rules](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/install/gcp/installer/forseti_server_installer.py#L164)

## Configuration
	* [forseti server conf](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/configs/server/forseti_conf_server.yaml.in)
	Make a copy of `forseti_conf_server.yaml.in` and call it `forseti_conf_server.yaml`
	Fill-in the placeholder values as denoted by `{FOOBAR_PLACEHOLDER}`
	Save it to `/home/ubuntu/forseti-security/configs`

	* [scanner rule files](https://github.com/GoogleCloudPlatform/forseti-security/tree/2.0-dev/rules)
	Fill-in the placeholder values as denoted by `{FOOBAR_PLACEHOLDER}`

	* copy the to GCS bucket
		** Copying the Forseti server configuration file to:
			gs://forseti-server-5ca974b/configs/forseti_conf_server.yaml
		** Copying the Forseti server deployment template to:
			gs://forseti-server-5ca974b/deployment_templates/
		** Copying the default Forseti rules to:
			gs://forseti-server-5ca974b/rules


# Create Database

## Create a [CloudSQL instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/deployment-templates/cloudsql/cloudsql-instance.py)
	* forseti-server-db-5ca974b
	* MySQL 5.7
	* second generation
	* vCPUs: 1
	* Memory: 3.75 GB
	* SSD storage: 25 GB
	* db-n1-standard-1


# Deploy Client VM

## Create a forseti client service account.
forseti-client-gcp-#######@fooproject.iam.gserviceaccount.com

## Assign roles:
	* roles/storage.objectViewer
	* roles/logging.logWriter

## Create a forseti [client VM instance](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/deployment-templates/compute-engine/client/forseti-instance-client.py).
	* n1-standard-2
	* ubuntu-1804-lts
	* bind the client service account to the VM instance
	* [enable computeOS login](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/install/gcp/installer/util/gcloud.py#L709)

## Install Forseti Client
	* ssh into the client VM
	* become ubuntu user
	* git clone the forseti release
	* run the steps in the startup-script

Configuration
	* [forseti client conf](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/configs/server/forseti_conf_client.yaml.in)
	TODO: where is the client yaml???
	Make a copy of `forseti_conf_server.yaml.in` and call it `forseti_conf_server.yaml`
	Fill-in the placeholder values as denoted by `{FOOBAR_PLACEHOLDER}`

	* Copy to GCS
		** Copying the Forseti client configuration file to:
		gs://forseti-client-#######/configs/forseti_conf_client.yaml
		** Copying the Forseti client deployment template to:
		gs://forseti-client-#######/deployment_templates/

GSuite Integration
	* [Enable DwD for the server service account](https://forsetisecurity.org/docs/howto/configure/gsuite-group-collection.html)
