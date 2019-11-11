---
title: Deploy Forseti Security on Google Kubernetes Engine
order: 004
---

{% include docs/v2.23/beta-release-feature.md %}

# {{ page.title }}

This guide explains how to setup Forseti on Kubernetes.  Most installation scenarios require the use of Terraform and the [terraform-google-forseti](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/) module.  The Forseti containers are deployed on-GKE using [Helm charts](https://github.com/forseti-security/helm-charts).  When using Terraform to deploy Forseti on-GKE, this is transparent to the user.

## Install Pre-Requisites

The following tools are required:
* [Terraform](https://www.terraform.io/downloads.html) - 0.12.x
* [gsutil](https://cloud.google.com/storage/docs/gsutil)


## Deploying with Terraform
The *on_gke** examples are found in the [examples/](https://github.com/forseti-security/terraform-google-forseti/tree/master/examples/) folder of the *terraform-google-forseti* Terraform module.  Each "on-GKE" specific example is prepended with "on_gke_".  Please understand that each of these examples are just that, examples.  Each example has a *main.tf* file that describes how the environment will be built addressing common scenarios.  Please review the examples to determine if the examples are sufficient for the environment where Forseti is deployed.

Wherever possible, the examples utilize [modules](https://registry.terraform.io/modules/terraform-google-modules) developed and curated by the [Cloud Foundation Toolkit](https://cloud.google.com/foundation-toolkit/) team.  These modules implement opinionated best practices for deploying GCP components.  For example, the [kubernetes-engine](https://registry.terraform.io/modules/terraform-google-modules/kubernetes-engine/google/5.0.0) module applies practices found in the [GKE hardening](https://cloud.google.com/kubernetes-engine/docs/how-to/hardening-your-cluster).

### Re-using an Existing Forseti Deployment
If you wish to reuse an existing Forseti deployment (e.g. you deployed Forseti on GCE with either Deployment Manager or Terraform), please follow the terraform-google-forseti [upgrade guide]({% link _docs/v2.23/setup/upgrade.md %}).

#### Service Account

{% include docs/v2.23/setup-script-credentials.md %}

{% include docs/v2.23/setup-script-credentials-gke.md %}

### Deploy Forseti on-GKE

Create a file named *main.tf* in an empty directory and add the following content per one of the two scenarios below.  Add the appropiate values for each of the input variables (e.g. domain, gsuite_admin_email).

#### New GKE Cluster
```bash
module "forseti-on-gke" {
    source                  = "terraform-google-modules/forseti/google//examples/on_gke_end_to_end"
    domain                  = ""
    gsuite_admin_email      = ""
    org_id                  = ""
    project_id              = ""
    region                  = ""
}
```

#### Existing GKE Cluster
```bash
module "forseti-on-gke" {
    source                  = "terraform-google-modules/forseti/google//examples/on_gke"
    domain                  = ""
    gsuite_admin_email      = ""
    org_id                  = ""
    project_id              = ""
    region                  = ""

    gke_cluster_name        = ""
    gke_cluster_location    = ""
}
```

#### Next Steps

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

Forseti can be deployed on-GKE without the use of Terraform if the following preconditions are met.

1. Forseti has been deployed in a GCP project.
2. A GKE cluster has already been deployed in GCP under the same organization as Forseti.
3. The [GKE credentials](https://cloud.google.com/kubernetes-engine/docs/how-to/cluster-access-for-kubectl) exist on the machine executing the deployement
4. The [Helm binary](https://helm.sh/docs/using_helm/) is installed and initiallized on the machine executing the deployment.

After these preconditions are met, add the *forseti-security-charts* Helm repo to your Helm environment.

```bash
helm repo add forseti-security https://forseti-security-charts.storage.googleapis.com/release
```

Follow the [chart installation instructions](https://hub.helm.sh/charts/forseti-security/forseti-security) to install Forseti on-GKE.


## Post Deployment Configuration Changes

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
    --set-string serverConfigContents="$(gsutil cat gs://<BUCKET_NAME>/configs/forseti_conf_server.yaml | base64 -)" \
    --values=forseti-values.yaml
```

### Deploying with config-validator on-GKE

The config-validator in Forseti on-GKE obtains policies from a policy-library in a Git repository via SSH.  The pre-requisites for this are as follows.

1. A [policy-library](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md#get-started-with-the-policy-library-repository) in a Git repository.
2. A generated SSH key with the private key local to the host running Terraform or Helm, and the public key uploaded to the service hosting the policy-library Git repository.

#### With Terraform

In any of the Terraform examples above, the following additional variables are required:

```bash
module "forseti-on-gke-with-config-validator" {
    # Other parameters/variables removed for brevity

    # Enable config-validator
    config_validator_enabled = true
    
    # Path to the private SSH key file
    git_sync_private_ssh_key_file = ""

    # SSH Git repository location, usually in the following
    # format: git@repo-host:repo-owner/repo-name.git
    policy_library_repository_url = ""
}
```

#### With Helm

In the Helm example above, the following variables are required in the user defined *values.yaml* file.

```yaml
# configValidator sets whether or not to deploy config-validator
configValidator: true

# gitSyncPrivateSSHKey is the private OpenSSH key generated to allow the git-sync to clone the policy library repository.
gitSyncPrivateSSHKey: ""

# gitSyncSSH use SSH for git-sync operations
gitSyncSSH: true

# policyLibraryRepositoryURL is a git repository policy-library.
policyLibraryRepositoryURL: ""

```
## Accessing Forseti from the Client VM
Forseti on-GKE is configured to accept connections from the CIDR on which the Client VM is deployed.  You can access the Forseti deployment, for example to run `forseti inventory create` by doing the following:

1. SSH to the Client VM.
1. Change user to the `ubuntu` user.
1. Execute the desired command.
