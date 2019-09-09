---
title: Deploy Forseti Security on Google Kubernetes Engine
order: 004
---

{% include docs/v2.20/alpha-release-feature.md %}

# {{ page.title }}

This guide explains how to setup Forseti on Kubernetes.  Most installation scenarios require the use of Terraform and the [terraform-google-forseti](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/) module.  The Forseti containers are deployed on GKE using [Helm charts](https://github.com/forseti-security/helm-charts).  When using Terraform to deploy Forseti on GKE, this is transparent to the user.

There are multiple scenarios for installation depending on what GCP components (GKE, Forseti) are installed, if any.  After addressing the [pre-requisites](#install-pre-requisites), please use the following table to determine from which step you should start.

{: .table}
|  An Empty GCP Project  |  Forseti Infrastructure  |  GKE Cluster  |  Then start at  |
|-------|-------|-------|-------|
| Yes | No | No | [Deploy Forseti and Forseti on GKE end-to-end](#deploy-forseti-and-forseti-on-gke-end-to-end) |
| No | Yes | No | [Deploy Forseti in a New GKE Cluster](#deploy-forseti-in-a-new-gke-cluster) |
| No | Yes | Yes | [Deploy Forseti in an Existing GKE Cluster](#deploy-forseti-in-an-existing-gke-cluster) |
| No | Yes | Yes | [Deploy Forseti in an Existing GKE Cluster (Helm)](#deploy-forseti-in-an-existing-gke-cluster-helm) |

## Install Pre-Requisites

The following tools are required:
* [Terraform](https://www.terraform.io/downloads.html) - 0.12.x
* [gsutil](https://cloud.google.com/storage/docs/gsutil)

## Deploying with Terraform

In each of the following scenarios, the user will create a *main.tf* file and add the appropriate input variables.  It is recommended that this *main.tf* be created in an empty directory.

Each scenario described below invokes a corresponding example in the [examples/](https://github.com/forseti-security/terraform-google-forseti/tree/master/examples/) folder of the *terraform-google-forseti* Terraform module.  Each "on-GKE" specific example is prepended with "on_gke_".  Please understand that each of these examples are just that, examples.  Each example has a *main.tf* file that describes how the environment will be built addressing common scenarios.  Please review the examples to determine if the examples are sufficient for the environment where Forseti is deployed.  

Each corresponding example in the [examples/](https://github.com/forseti-security/terraform-google-forseti/tree/master/examples/) folder on GitHub also contains additional information on each deployment scenario.

Wherever possible, the examples utilize [modules](https://registry.terraform.io/modules/terraform-google-modules) developed and curated by the [Cloud Foundation Toolkit](https://cloud.google.com/foundation-toolkit/) team.  These modules implement opinionated best practices for deploying GCP components.  For example, the [kubernetes-engine](https://registry.terraform.io/modules/terraform-google-modules/kubernetes-engine/google/4.0.0) module applies practices found in the [GKE hardening](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster).

### Deploy Forseti and Forseti on GKE end-to-end

Create a file named *main.tf* in an empty directory and add the following content.  Add the appropiate values for each of the input variables (e.g. domain, gsuite_admin_email).

```bash
module "forseti-on-gke-end-to-end" {
    source                  = "terraform-google-modules/forseti/google//examples/on_gke_end_to_end"
    credentials_path        = ""
    domain                  = ""
    gsuite_admin_email      = ""
    org_id                  = ""
    project_id              = ""
    region                  = ""
    zones                   = [""]
    network_description     = "GKE Network"
    auto_create_subnetworks = false
    gke_node_ip_range       = "10.1.0.0/20"
}
```

Initialize the Terraform module.

```bash
terraform init
```

Apply the Terraform module.

```bash
terraform apply
```

**Note:** The `terraform apply` may fail to complete.  In this case, please re-run `terraform apply`.

### Deploy Forseti in a New GKE Cluster

Create a file named *main.tf* in an empty directory and add the following content.  Add the appropiate values for each of the input variables (e.g. domain, gsuite_admin_email).

```bash
module "forseti-on-gke-new-gke-cluster" {
    source                           = "terraform-google-modules/forseti/google//examples/on_gke_new_gke_cluster"
    credentials_path                 = ""
    forseti_client_service_account   = "SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com" 
    forseti_client_vm_ip             = ""
    forseti_cloudsql_connection_name = ""
    forseti_server_service_account   = "SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com"
    forseti_server_storage_bucket    = "BUCKET_ID_without_gs"
    project_id                       = ""
    region                           = ""
	# The suffix can be obtained from the name of the
	# existing Forseti VM's: forseti-server-[SUFFIX]
    suffix                           = ""
    zones                            = [""]
    network_description              = ""
    auto_create_subnetworks          = false
	# This is the subnet CIDR on the subnet
	# where Forseti is installed.
    gke_node_ip_range                = "10.1.0.0/20"
	network_name				     = ""
	subnetwork_name					 = ""
}
```

Initialize the Terraform module.

```bash
terraform init
```

Apply the Terraform module.

```bash
terraform apply
```

**Note:** The `terraform apply` may fail to complete.  In this case, please re-run `terraform apply`.

### Deploy Forseti in an Existing GKE Cluster

Create a file named *main.tf* in an empty directory and add the following content.  Add the appropiate values for each of the input variables (e.g. domain, gsuite_admin_email).

```bash
module "forseti-on-gke-existing-gke-cluster" {
    source                           = "terraform-google-modules/forseti/google//examples/on_gke_existing_gke_cluster"
    credentials_path                 = ""
    forseti_client_service_account   = "SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com"
    forseti_client_vm_ip             = ""
    forseti_cloudsql_connection_name = ""
    forseti_server_service_account   = "SERVICE_ACCOUNT_NAME@PROJECT_ID.iam.gserviceaccount.com"
    forseti_server_storage_bucket    = "BUCKET_ID_without_gs"
    gke_cluster_name                 = ""
    gke_cluster_location             = ""
    gke_service_account              = ""
    project_id                       = ""
	# The suffix can be obtained from the name of the
	# existing Forseti VM's: forseti-server-[SUFFIX]
    suffix                           = ""
}
```

Initialize the Terraform module.

```bash
terraform init
```

Apply the Terraform module.

```bash
terraform apply
```

## Deploying with Helm

### Deploy Forseti in an Existing GKE Cluster (Helm)

Forseti can be deployed on GKE without the use of Terraform if the following preconditions are met.

1. Forseti has been deployed in a GCP project.
2. A GKE cluster has already been deployed in GCP under the same organization as Forseti.
3. The [GKE credentials](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl) exist on the machine executing the deployement
4. The [Helm binary](https://helm.sh/docs/using_helm/) is installed and initiallized on the machine executing the deployment.

After these preconditions are met, add the *forseti-security-charts* Helm repo to your Helm environment.

```bash
helm repo add forseti-security https://forseti-security-charts.storage.googleapis.com/release
```

Create and download [IAM service account keys](https://cloud.google.com/iam/docs/creating-managing-service-account-keys) in JSON format for the **forseti-server** and **forseti-client** service accounts.

Follow the [chart installation instructions](https://github.com/forseti-security/helm-charts/tree/master/charts/forseti-security#installing-the-forseti-security-chart) to install Forseti on GKE.


## Post Deployment Configuration Changes

After deploying Forseti, the default server configuration defines

```yaml
    rules_path: /home/ubuntu/forseti-security/rules
```

This path doesn't exist in the container.  Instead, the value of `rules_path` must point to the rules path in the Forseti server GCS bucket.  The can be changed by executing the following.

1. Obtain the *forseti_server_conf.yaml* file from the GCS bucket.
```bash
gsutil cp gs://[FORSETI_SERVER_BUCKET]/configs/forseti_server_conf.yaml forseti_server_conf.yaml
```

2. Edit the forseti_server_conf.yaml file so that the `rules_path` points to the rules folder in the GCS bucket.
```yaml
    rules_path: gs://[FORSETI_SERVER_BUCKET]/rules
```

3. Save the file and exit the editor.

4. Copy the *forseti_server_conf.yaml* file back to GCS.
```bash
gsutil cp forseti_server_conf.yaml gs://[FORSETI_SERVER_BUCKET]/configs/forseti_server_conf.yaml
```

5. Ensure the *Content-Type* of the *forseti_server_conf.yaml* is `text/plain`.
```bash
gsutil setmeta -h "Content-Type:text/plain; charset=utf-8" gs://[FORSETI_SERVER_BUCKET]/configs/forseti_conf_server.yaml
```

### Reload Forseti on GKE

**Note:** If any changes are made to the *forseti_server_conf.yaml* file in GCS, one of the following steps is necessary.  In a future version of this feature, this will be automated.

#### With Terraform
```bash
terraform apply
```

#### With Helm
```
helm upgrade -i forseti forseti-security/forseti-security \
    --set production=true \
    --recreate-pods \
    --set-string serverKeyContents="$(cat forseti-server.json | base64 - -w 0)" \
    --set-string orchestratorKeyContents="$(cat forseti-client.json | base64 - -w 0)" \
    --set-string serverConfigContents="$(gsutil cat gs://<BUCKET_NAME>/configs/forseti_conf_server.yaml | base64 -)" \
    --values=forseti-values.yaml
```
### Troubleshooting

#### Terraform Apply - Error creating Network: googleapi: Error 409

##### Error Message
```bash
Error: Error creating Network: googleapi: Error 409: The resource 'projects/[PROJECT_ID]/regions/us-central1/subnetworks/[SUBNETWORK_NAME]' already exists, alreadyExists
```

##### Explanation
This error occurs when attempting to deploy to a network and subnetwork that already exist, for example the "default" network.

##### Workaround
1. Remove any state files in the working directory
```bash
rm -rf terraform.tfstate*
```

2. Import existing network resource into Terraform state
```bash
terraform import module.forseti-on-gke-new-gke-cluster.module.vpc.google_compute_network.network projects/[PROJECT_ID]/global/networks/default
```

3. Import existing subnetwork resource into Terraform state
```bash
terraform import module.forseti-on-gke-new-gke-cluster.module.vpc.google_compute_subnetwork.subnetwork[0] projects/[PROJECT_ID]/regions/us-central1/subnetworks/default
```

4. In the user defined module ensure the following values match the values in the existing resource
	* `network_description`
	* `auto_create_subnetworks`
	* `gke_node_ip_range` - This is the subnet range of the VPC subnet

<br />
#### Terraform Apply - connect: connection refused when deploying Forseti via Tiller

##### Error Message
```
Error: Get https://35.239.190.141/apis/apps/v1/namespaces/forseti-84cd80fe/deployments/tiller-deploy: dial tcp 35.239.190.141:443: connect: connection refused
```

##### Explanation
This happens when the GKE cluster is not able to schedule pods when Terraform attempts to deploy Forseti on the cluster via Helm.  This is to be addressed via a patch in a future version of the [terraform-google-kubernetes-engine](https://github.com/terraform-google-modules/terraform-google-kubernetes-engine) module.

##### Workaround
Re-run `terraform apply`
```
terraform apply
```
<br />
#### Terraform Destroy - Error, failed to deleteuser root 

##### Error Message
```bash
Error: Error, failed to deleteuser root in instance forseti-server-db-1914b4e1: googleapi: Error 400: Missing parameter: host., required
```

##### Explanation
This is under investigation.  Please see forseti-security/forseti-security GitHub [issue #148](https://github.com/forseti-security/terraform-google-forseti/issues/148).  

##### Workaround
```bash
terraform state rm module.forseti-on-gke-end-to-end.module.forseti.module.server.google_sql_user.root
```

<br />
#### Terraform Destroy - could not find a ready tiller pod

##### Error Message
```bash
Error: error creating tunnel: "could not find a ready tiller pod"
```

##### Explanation
This occurs if the GKE cluster is destroyed before Terraform destroys the Helm release.  This will be resolved in the near future.  While this issue has been resolved via terraform-google-modules/terraform-google-kubernetes-engine [pull request #214](https://github.com/terraform-google-modules/terraform-google-kubernetes-engine/pull/214), this documentation will remain for reference.

##### Workaround
```bash
terraform state rm module.forseti-on-gke-end-to-end.module.forseti-on-gke.helm_release.forseti-security

terraform state rm module.forseti-on-gke-end-to-end.module.forseti-on-gke.kubernetes_namespace.forseti
```

<br />
#### Terraform Destroy - Cannot delete auto subnetwork

##### Error Message
```bash
Error: Error reading Subnetwork: googleapi: Error 400: Invalid resource usage: 'Cannot delete auto subnetwork from an auto subnet mode network.'., invalidResourceUsage
```

##### Explanation
This occurs when there are resources on the subnetwork that exist outside of Terraform's state.  For instance, Forseti may have been deployed in a separate run of Terraform.

##### Workaround
```bash
terraform state rm module.forseti-on-gke-new-gke-cluster.module.vpc.google_compute_network.network

terraform state rm module.forseti-on-gke-new-gke-cluster.module.vpc.google_compute_subnetwork.subnetwork[0]
```
#### Terraform - Help, my error isn't listed here.
There are a few things you can do.
1. Run `terraform apply` or `terraform destroy` again to see if the error occurs repeatedly.
2. Open an issue against the [Terraform Google Forseti](https://github.com/forseti-security/terraform-google-forseti/issues) module
3. Post an issue in our [Slack Channel](https://forsetisecurity.slack.com/join/shared_invite/enQtNDIyMzg4Nzg1NjcxLTJhYjI1YzY0MDg4YjRhMDhhZTMwZTg0MWExZjU1MTNiNWFmMmFlMWQ0MmI3OTE1MzczZTMwNTEzNDZiNDY3NTY).  We'll be happy to try and help!
