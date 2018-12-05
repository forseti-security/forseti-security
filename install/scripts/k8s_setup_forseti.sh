#!/bin/bash

# kubernetes example deployment script for Proof of Concept purposes

# Create Cluster
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

	CREDENTIALS=<path>/<keyfilename>.json
	kubectl create secret generic credentials --from-file=key.json=${CREDENTIALS}

	# Optionally verify
	# kubectl get secret credentials -o yaml

# Deploy forseti app

	# TODO set environment variables needed to create forseti.yaml
	export FORSETI_IMAGE=gcr.io/<project>/<image>
	export BUCKET=gs://<bucketname>
	export CLOUD_SQL_CONNECTION=<project>:<region>:<db>

	# Create a deployment file 'forseti.yaml' from the template 'forseti.template.yaml'
	# with variables substituted into the yaml
	# We do this because kubectl apply doesnt support environment variable substitution
	envsubst < forseti.template.yaml > forseti.yaml

	kubectl apply -f forseti.yaml

