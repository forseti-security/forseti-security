---
title: Exciting Changes to Forseti and Terraform in 2.23
author: Ken Evensen and Hannah Shin
---

Forseti Community,

With Forseti 2.23 we have a lot of exciting changes.  

### Forseti Optimization
The Forseti team has been focused on delivering a faster, more efficient inventory process. These improvements will be more prominent for organizations that have 1 million+ resources -- most users can expect to see a significant reduction in the time it takes to create an inventory. 

These improvements come from both code and infrastructure optimizations.  For infrastructure, we have decided to increase the default Forseti VM and Cloud SQL instances. Going forward, the Forseti server VM will default to n1-standard-8 and Cloud SQL will default to db-n1-standard-4.

If your Forseti scans still take longer than 24 hours or your Forseti inventory creation does not see a reduction in time, please reach out to us on Slack for help profiling your environment. These improvements are targeted for inventory data collection from the Cloud Asset Inventory (CAI) datasource.  Customers getting data by time intensive GCP API calls will not see the improvements.  We are working with the CAI team to migrate the remaining resources from API into the CAI datasource.

### Forseti Config Validator Performance Optimization
Forseti Config Validator has been updated to evaluate multiple policies on the same dataset in parallel. Customers using Config Validator scanners with Forseti will now see more efficient scanning of large GCP environments.

### Migration to Terraform Installer
Forseti now supports Terraform as the official installation path. As we outlined in our previous [post]({% link _news/2019-09-17-deprecate-python-installer.md %}), we have deprecated the Python based installer.  Additionally, we have removed the related Python installer code from the forseti-security repo. 

We have created a migration script and documentation to help you seamlessly 
migrate from the Python installer to Terraform:

* For versions earlier than v2.18.0, please upgrade incrementally to v2.18.0 through 
Deployment Manager following the steps [here](/docs/latest/setup/upgrade.html) 
first before migrating.

You can learn more about the Forseti Terraform module source code 
[here](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/).

### Forseti Terraform Module Updates
The Terraform Forseti module has been restructured to support flexible deployment scenarios.  If you have previously installed Forseti using Terraform, you can migrate your existing Terraform state by following the instructions in the [upgrade guide](/docs/latest/setup/upgrade.html) 

### Forseti on-GKE Enters Beta
We are excited to announce that Forseti on-GKE is now released into Beta.  This is the result of considerable community collaboration over the last few months and we appreciate all who contributed to this effort.  There are several key features that make this feature robust, flexible, and secure:
* [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) is a Beta feature in GKE which allows Kubernetes Service Accounts to be mapped to IAM Service Accounts in a GCP project.  This means that there is no need to generate IAM Service Account Keys to be deployed as Kubernetes Secrets, resulting in a simpler and more secure deployment.
* The [Config Validator chart](https://github.com/forseti-security/helm-charts/tree/master/charts/config-validator) is deployed as a Helm dependency of the Forseti Security chart.  The Config Validator uses [git-sync](https://github.com/kubernetes/git-sync) to periodically pull updated policies into the config-validator container.  This [policy-library](https://github.com/forseti-security/policy-library) can either be public or private and accessed over HTTPS or SSH.  Additionally, the Config Validator chart can be deployed independently of Forseti as a standalone service in GKE.

Please reach out to us on [Slack](https://forsetisecurity.slack.com/) or discuss@forsetisecurity.org with any questions.
