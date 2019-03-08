---
title: Deploy Forseti Security on Kubernetes
order: 004
---

# {{ page.title }}

This guide explains how to setup Forseti on Kubernetes.

If you decide to use this in production, consider implementing the
[k8s hardening recommendations](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster),
as well as [CIS Benchmarks for GCP, section 7, Kubernetes](https://learn.cisecurity.org/benchmarks").

Note: This is a starting point to iterate and improve upon before
releasing a smoother installation approach for general usage, possibly by
using pre-built images stored on a public repo such as DockerHub.

---

## Pre-Requistes

Install Forseti server and client using the [standard
installer]({% link _docs/latest/setup/install.md %}) or the [terraform
installer](https://github.com/terraform-google-modules/terraform-google-forseti).
This is a quick way to install the service accounts, Cloud SQL and GCS buckets.
The VM's may be deleted or shutdown after the install as they will be replaced
by the k8s solution.

Alternatively follow the [manual setup instructions]({% link _docs/latest/setup/manual.md %})
for service accounts, Cloud SQL and GCS buckets.

## Build Docker Image

There are various ways to build the docker image, using git clone or
a personal fork.

BUILD IMAGE (git clone example)
```
Clone the forseti security repo to the Cloud Shell VM in your project
cd to forseti-security directory
git checkout dev (or other branch)
gcloud builds submit --config install/docker/cloudbuild.yaml .
(Dont forget the dot at the end)
```
Ref. https://cloud.google.com/cloud-build/docs/quickstart-docker#build_using_a_build_config_file

BUILD IMAGE (Forked repo trigger example)
```
Create a fork of the forseti security repository in github.
Create a Cloud Build Trigger to automatically build when changes pushed to your forked repo
Specify the branch (e.g. dev)
Specify the cloudbuild.yaml build config file
```

Example:
{% responsive_image path: images/docs/setup/k8s_cloud_build.png alt: "k8s cloud build" %}

## Deploy to Kubernetes

1. Open a cloud shell VM in your project.
1. Upload the server and client service account keys to Cloud Shell.
Note the file locations for later.
1. Clone your forked repo and switch to the `dev` branch.
1. Modify [forseti-security/install/scripts/k8s_setup_forseti.sh](https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/k8s_setup_forseti.sh)
* setting the environment variables
* paths to your service account keys
* choose the architecture, either k8s CronJob or long running server
1. `cd to ../forseti-security/install/scripts/` and run the `k8s_setup_forseti.sh` script.

NOTE: In client config file in GCS bucket, change IP of forseti-server
to match the Cluster Ip of Forseti Service

Ref. https://github.com/GoogleCloudPlatform/forseti-security/blob/docker-poc/install/scripts/k8s_setup_forseti.sh

## Verify

Monitor the deployment in the GKE web console. Allow approximately 2 minutes
for the cluster to spin up and another 30 seconds for the pods to become active.

Long running server example:
{% responsive_image path: images/docs/setup/k8s_long_running_server.png alt: "k8s long running server" %}

Run `kubectl get pods` to get pod ids
Connect: `kubectl exec -it <CLIENT_POD_ID> -- /bin/bash`

Run Forseti commands to verify that Forseti server is working as expected.

## k8s Cron Job

Note: The long running server approach doesn't have an internal cron yet,
so use the CronJob approach for now if periodic scans needed.

k8s CronJob example:
{% responsive_image path: images/docs/setup/k8s_cron_job.png alt: "k8s cron job" %}

Drill into Forseti Workload to see Job History
{% responsive_image path: images/docs/setup/k8s_job_history.png alt: "k8s job history" %}

## File Notes

File | Changes to Support GKE
-- | --
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/.dockerignore | Added .dockerignore to reduce Docker image size.
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/dependencies/apt_packages.txt | Add cron (to install on base image)
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/docker/base | Install Google Cloud SDK on base image
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/docker/cloudbuild.yaml | Added optional cache base image build step to reduce build time. Added optional unit tests build step
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/docker/forseti | chmod +x docker_entrypoint.sh
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/cloudsqlproxy.service.template.yaml | Cloud SQL Proxy Cluster IP Service Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/cloudsqlproxy.template.yaml | Cloud SQL Proxy Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/docker_entrypoint.sh | docker_entrpoint.sh initialises the container, starts services, runs scan as needed.
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/forseti.client.template.yaml | Forseti Client Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/forseti.cronjob.template.yaml | Forseti CronJob Template
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/forseti.server.service.template.yaml | Forseti Server Cluster IP Service Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/forseti.server.template.yaml | Forseti Server Deployment template
https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/install/scripts/k8s_setup_forseti.sh | Example script to spin up cluster and deploy Forseti to GKE
