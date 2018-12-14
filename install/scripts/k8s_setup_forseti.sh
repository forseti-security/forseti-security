#!/bin/bash

# kubernetes example deployment script for Proof of Concept purposes

# Create Cluster
	# TODO set as needed
	CLUSTER=forseti
	ZONE=us-central1-c
	MACHINE=n1-standard-2
	NODES=1
	gcloud config set compute/zone ${ZONE}
	gcloud container clusters create ${CLUSTER} --num-nodes=${NODES} --machine-type=${MACHINE}

# Create Secret 'credentials' containing file 'key.json'
# copied from the forseti service account credentials file.

	# Set default cluster for gcloud / kubectl
	gcloud config set container/cluster ${CLUSTER}

	# TODO set credentials variable
	CREDENTIALS=<path>/<keyfilename>.json
	kubectl create secret generic credentials --from-file=key.json=${CREDENTIALS}

	# Optionally verify
	# kubectl get secret credentials -o yaml

# Deploy forseti app

	# TODO set environment variables needed to create forseti.yaml
	export FORSETI_IMAGE=gcr.io/<project>/<image>
	export BUCKET=gs://<bucketname>
	export CLOUD_SQL_CONNECTION=<project>:<region>:<db>
	export CRON_SCHEDULE="*/60 * * * *"

	# Create a deployment file 'forseti.yaml' from the template 'forseti.yaml.template'
	# with variables substituted into the yaml
	# We do this because kubectl apply doesnt support environment variable substitution
	envsubst < cloudsqlproxy.template.yaml > cloudsqlproxy.yaml
	envsubst < forseti.template.yaml > forseti.yaml

	kubectl apply -f cloudsqlproxy.yaml
	kubectl apply -f cloudsqlproxyservice.yaml
	# Be sure to start cloud sql proxy service before forseti as forseti docker_entrypoint.sh
	# uses the CLOUDSQLPROXY_SERVICE_HOST and CLOUDSQLPROXY_SERVICE_PORT environment variables
	# that are automatically created by k8s
	kubectl apply -f forseti.yaml
