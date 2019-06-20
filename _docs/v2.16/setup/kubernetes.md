---
title: Deploy Forseti Security on Kubernetes
order: 004
---

# {{ page.title }}

This guide explains how to setup Forseti on Kubernetes.

This is a proof of concept (POC) in the `dev` branch.

If you decide to use this, consider implementing the
[k8s hardening recommendations](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster),
as well as [CIS Benchmarks for GCP, section 7, Kubernetes](https://learn.cisecurity.org/benchmarks).

## 0. Install Pre-Requistes

Create (or use) a project with Forseti PaaS dependencies deployed:
GCS buckets, Cloud SQL DB and Service Account(s)

Install Forseti server and client using
* the [standard installer]({% link _docs/v2.16/setup/install.md %})
* or the [terraform installer](https://github.com/terraform-google-modules/terraform-google-forseti).

We are using dev branch for the POC.

The VM's may be deleted or shutdown after the install as they will be replaced
by the k8s solution.

Remaining steps can be run from a Google Cloud Shell VM in Forseti GCP project.

## 1. Obtain Service Account Keys

[Download the Forseti server (and optionally client) service account
keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys#creating_service_account_keys)
and store them locally on the Cloud Shell VM temporarily for k8s secret
creation. It is your responsibility to keep the key files secure.

## 2. Clone the Forseti Security Git Repo

```
git clone https://github.com/GoogleCloudPlatform/forseti-security.git
cd forseti-security
git checkout dev
```

## 3. Build Docker Image

```
gcloud builds submit --config install/docker/cloudbuild.yaml .
```

Dont forget the dot at the end.

Ref. https://cloud.google.com/cloud-build/docs/quickstart-docker#build_using_a_build_config_file


## 4. Edit the Example Kubernetes Deployment Script

```
cd install/scripts
vi k8s_setup_forseti.sh
```

Specify the variables

* New cluster spec or name of existing cluster
* Path to service account keys
* Forseti GCS buckets
* MySQL connection string
* Type of k8s deployment: CronJob or long running server (+ optional client)
* Cron schedule


## 5. Update Client Config File with Forseti Service IP

If using the client, modify the client config file in the GCS bucket to point
to the Forseti Server Cluster IP.

[forseti-security/install/scripts/k8s_setup_forseti.sh](https://github.com/forseti-security/forseti-security/blob/release-2.16.0/install/scripts/k8s_setup_forseti.sh)
```
export FORSETI_SERVER_IP=10.43.240.3 # k8s Cluster IP for Forseti Server. Don't forget to manually add this to the Client config file in GCS bucket if using Client. 
```

[forseti-security/configs/client/forseti_conf_client.yaml.sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/configs/client/forseti_conf_client.yaml.sample)
```
server_ip: <server cluster ip>
```

We will move away from this hard coded approach, however this is the current
POC implementation.

## 6. Update the rules_path in server config

If Scanner rules_path defaulted to `/home/ubuntu/forseti-security/rules`,
change it to use the GCS bucket directly:

[forseti-security/configs/server/forseti_conf_server.yaml.sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/983d2952eb48d8c5928b1fbd5113eef2ee2e7905/configs/server/forseti_conf_server.yaml.sample#L192-L197)
```
rules_path: gs://<server bucket>/rules
```

## 7. Run the Kubernetes Deployment Script (from its directory)

```
./k8s_setup_forseti.sh
```

## 8. Verify

Monitor the deployment in the GKE web console. Allow approximately 2 minutes
for the cluster to spin up and another 30 seconds for the pods to become active.

### Long Running Server Example
{% responsive_image path: images/docs/setup/k8s_long_running_server.png alt: "k8s long running server" %}

Run `kubectl get pods` to get pod ids
Connect: `kubectl exec -it <CLIENT_POD_ID> -- /bin/bash`

Run Forseti commands to verify that Forseti server is working as expected.

### k8s Cron Job Example

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
