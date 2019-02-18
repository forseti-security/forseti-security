---
title: Deploy Forseti Security on Kubernetes
order: 004
---

# {{ page.title }}

This guide explains how to setup Forseti on Kubernetes.

Note: The current work here is considered not yet ready for production use.
Instead, it is to be a starting point to iterate and improve upon before
releasing a smoother installation approach for general usage, possibly by
using pre-built images stored on a public repo such as DockerHub.

Thanks to [@Red-Five](https://github.com/Red-Five) for contributing
the work and the documentations!

---

## Pre-Requistes

Install Forseti server and client using the standard
[installer]({% link _docs/latest/setup/install.md %}). This is a
quick way to install the service accounts, Cloud SQL and GCS buckets.
The VM's may be deleted after the install.

Alternatively follow the [manual setup instructions]({% link _docs/latest/setup/manual.md %})
for service accounts, Cloud SQL and GCS buckets.

## Build Docker Image

There are various ways to build the docker image, but to show one example,
create a personal fork of the [Forseti Security repository in GitHub](https://github.com/GoogleCloudPlatform/forseti-security).
This will be used by Google Cloud Build to build the Forseti image.

The k8s proof-of-concept code is in the `docker-poc` branch.
Optionally merge `dev` branch or a tagged release into the `docker-poc`
branch so that the image has desired version of the code base.

Create a Google Cloud Build trigger against your fork and the
`docker-poc` branch, then manually trigger the build.

Note: [cloudbuild.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/docker/cloudbuild.yaml)
base image cache step will fail first time as their is no base image to cache,
comment this out manually if it's not yet commented out in the codebase.


Example:
{% responsive_image path: images/docs/setup/k8s_cloud_build.png alt: "k8s cloud build" %}

## Deploy to Kubernetes

1. Open a cloud shell VM in your project.
1. Upload the server and client service account keys to Cloud Shell.
Note the file locations for later.
1. Clone your forked repo and switch to the `docker-poc` branch.
1. Modify [forseti-security/install/scripts/k8s_setup_forseti.sh](https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/k8s_setup_forseti.sh); 
setting the environment variables and paths to your service account keys and
choose the architecture, either k8s CronJob or long running server
1. `cd to ../forseti-security/install/scripts/` and run the `k8s_setup_forseti.sh` script.

## Verify

Monitor the deployment in the GKE web console. Allow approx. 2 minutes for the
cluster to spin up and another 30 seconds for the pods to become active

Long running server example:
{% responsive_image path: images/docs/setup/k8s_long_running_server.png alt: "k8s long running server" %}

Run `kubectl get pods` to get pod ids
Connect: kubectl exec -it <CLIENT POD_ID> -- /bin/bash

After connecting to client, source the environment variables before
running Forseti CLI commands:
`. /etc/profile.d/forseti_environment.sh`

Run Forseti commands to verify that Forseti server is working as expected.

## Cron Job

Note: The long running server approach doesn't have an internal cron yet,
so use the CronJob approach for now if periodic scans needed.

k8s CronJob example:
{% responsive_image path: images/docs/setup/k8s_cron_job.png alt: "k8s cron job" %}

## File Notes

File | Changes to Support GKE
--- | ---
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/docker/base | Install Google Cloud SDK on base   image
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/docker/forseti | chmod +x docker_entrypoint.sh
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/docker/cloudbuild.yaml | Optionally cache base image   build step     Optionally include unit tests build step
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/cloudsqlproxy.service.template.yaml | Cloud SQL Proxy Cluster IP   Service Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/cloudsqlproxy.template.yaml | Cloud SQL Proxy Deployment   template
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/docker_entrypoint.sh | docker_entrpoint.sh initialises   the container, starts services, runs scan as needed.
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/forseti.client.template.yaml | Forseti Client Deployment   template
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/forseti.cronjob.template.yaml | Forseti CronJob Template
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/forseti.server.service.template.yaml | Forseti Server Cluster IP   Service Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/forseti.server.template.yaml | Forseti Server Deployment   template
https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/k8s_setup_forseti.sh | Example script to spin up   cluster and deploy Forseti to GKE
