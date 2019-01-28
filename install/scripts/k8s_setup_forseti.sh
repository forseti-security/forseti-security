#!/bin/bash

# kubernetes example deployment script for Proof of Concept purposes
# Assumes
#  script is running from Google Cloud Shell VM
#  active project is where the k8s cluster will spin up
#  GKE API is enabled on the project
#  user authorised to administer GKE
#  user has uploaded the forseti service account credentials json file to the cloud shell VM

# WARNINGS
# User is responsible for secure handling of the forseti service account credentials file
# This Proof of Concept has not been reviewed for security vulnerabilities; run this in a Sandbox environment

# Exit script on error
set -e

# Print commands
set -x

## VARIABLES, need to be set before running
# Variables for cluster creation (development defaults), what is appropriate disk size for production?
CLUSTER=forseti-cluster
ZONE=us-central1-c
NODES=1
MACHINE=n1-standard-2
DISK_SIZE=10GB

# Full path to Forseti service account credentials json file
# Needed to create k8s secret
SERVER_CREDENTIALS="" #TODO <path>/<keyfilename>.json
CLIENT_CREDENTIALS="" #TODO <path>/<keyfilename>.json

# Control which architecture to deploy
# CronJob just runs forseti server as k8s CronJob on the cron schedule and shuts it down after each run
# Server runs forseti server as k8s Cluster IP Service and keeps it running indefinitely
# Client, for now use this in conjunction with server to spin up client cli container on same cluster
# as server and connect to it via Cluster IP service
DEPLOY_CRONJOB=false
DEPLOY_SERVER=true
DEPLOY_CLIENT=true

# Environment variables needed to create deployment files from templates
# TODO is the export keyword needed?
export FORSETI_IMAGE=#gcr.io/${GOOGLE_CLOUD_PROJECT}/forseti:latest
export BUCKET=#gs://<bucketname>
export CLOUD_SQL_CONNECTION=#<project>:<region>:<db>
export CRON_SCHEDULE="*/60 * * * *"
export CLOUDSQL_IP=10.43.240.2
export FORSETI_SERVER_IP=10.43.240.3
## END VARIABLES

# Create Cluster
	gcloud config set compute/zone ${ZONE}

	# Use beta to enable latest stackdriver k8s monitoring
	gcloud beta container clusters create ${CLUSTER} --num-nodes=${NODES} --machine-type=${MACHINE} \
	--disk-size=${DISK_SIZE} --enable-stackdriver-kubernetes

# Create Secret 'credentials' containing file 'key.json'
# copied from the forseti service or client account credentials file.

	# Set default cluster for gcloud / kubectl
	gcloud config set container/cluster ${CLUSTER}

	kubectl create secret generic server-credentials --from-file=key.json=${SERVER_CREDENTIALS}

	# Optionally verify
	# kubectl get secret credentials -o yaml


	if ${DEPLOY_CLIENT}; then
	    kubectl create secret generic client-credentials --from-file=key.json=${CLIENT_CREDENTIALS}
    fi

# Create deployment files from the templates
# We do this because kubectl apply doesn't support environment variable substitution
	envsubst < cloudsqlproxy.template.yaml > cloudsqlproxy.yaml
	envsubst < cloussqlproxy.service.template.yaml > cloussqlproxy.service.yaml

	envsubst < forseti.cronjob.template.yaml > forseti.cronjob.yaml

	envsubst < forseti.server.template.yaml > forseti.server.yaml
	envsubst < forseti.server.service.template.yaml > forseti.server.service.yaml

	envsubst < forseti.client.template.yaml > forseti.client.yaml


if ${DEPLOY_CRONJOB}; then
    # Example forseti as k8s CronJob
    # Deploy Cloud SQL Proxy in its own pod
    # Create a Cluster IP Service for Cloud SQL Proxy
    # Deploy forseti as k8s CronJob
	kubectl apply -f cloudsqlproxy.yaml
	kubectl apply -f cloudsqlproxy.service.yaml
	kubectl apply -f forseti.cronjob.yaml

elif ${DEPLOY_SERVER}; then
    # Example, forseti server as k8s Cluster IP Service
    # Deploy Cloud SQL Proxy in its own pod
    # Create a Cluster IP Service for Cloud SQL Proxy
    # Deploy forseti server in its own pod
    # Create a Cluster IP Service for forseti server
 	kubectl apply -f cloudsqlproxy.yaml
	kubectl apply -f cloudsqlproxy.service.yaml
	kubectl apply -f forseti.server.yaml
	kubectl apply -f forseti.server.service.yaml
fi

if ${DEPLOY_CLIENT}; then
    kubectl apply -f forseti.client.yaml
fi