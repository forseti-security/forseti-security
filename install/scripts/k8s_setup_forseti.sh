#!/bin/bash

# kubernetes example deployment script for Proof of Concept purposes

# Create Cluster
	# TODO set as needed
	CLUSTER=forseti
	ZONE=us-central1-c
	NODES=1
	MACHINE=n1-standard-2
	DISK_SIZE=10GB

	gcloud config set compute/zone ${ZONE}

	# Use beta to enable latest stackdriver k8s monitoring
	gcloud beta container clusters create ${CLUSTER} --num-nodes=${NODES} --machine-type=${MACHINE} \
	--disk-size=${DISK_SIZE} --enable-stackdriver-kubernetes

# Create Secret 'credentials' containing file 'key.json'
# copied from the forseti service account credentials file.

	# Set default cluster for gcloud / kubectl
	gcloud config set container/cluster ${CLUSTER}

	# TODO set credentials variable
	CREDENTIALS=<path>/<keyfilename>.json
	kubectl create secret generic credentials --from-file=key.json=${CREDENTIALS}

	# Optionally verify
	# kubectl get secret credentials -o yaml

# Deploy Cloud SQL Proxy in its own pod
# Create a Cluster IP Service for Cloud SQL Proxy
# Deploy forseti as k8s CronJob

	# TODO set environment variables needed to create forseti.yaml and cloudsqlproxy.yaml
	export FORSETI_IMAGE=gcr.io/<project>/<image>
	export BUCKET=gs://<bucketname>
	export CLOUD_SQL_CONNECTION=<project>:<region>:<db>
	export CRON_SCHEDULE="*/60 * * * *"

	# Create deployment files from the templates
	# We do this because kubectl apply doesnt support environment variable substitution
	envsubst < cloudsqlproxy.template.yaml > cloudsqlproxy.yaml
	envsubst < forseti.cronjob.template.yaml > forseti.cronjob.yaml

	kubectl apply -f cloudsqlproxy.yaml
	kubectl apply -f cloudsqlproxyservice.yaml
	kubectl apply -f forseti.cronjob.yaml
