---
title: Exciting Changes to Forseti and Terraform in 2.23
author: Ken Evensen and ...
---

Forseti Community,

With Forseti 2.23 come some exciting changes.  

### Python Installer Deprecation
As we outlined in our previous [post]({% link _news/2019-09-17-deprecate-python-installer.md %}), we have deprecated the Python based installer.  Additionaly, we have removed the related Python installer code from the forseti-security repo. Forseti now supports Terraform as the official installation path.

We have created a migration script and documentation to help you seamlessly 
migrate from Deployment Manager to Terraform:

* For v2.18.0+ users, refer to the instructions to migrate 
[here](/docs/latest/setup/migrate.html).

* For versions earlier than v2.18.0, please upgrade incrementally to v2.18.0 through 
Deployment Manager following the steps [here](/docs/latest/setup/upgrade.html) 
first before migrating.

You can learn more about the Forseti Terraform module source code 
[here](https://registry.terraform.io/modules/terraform-google-modules/forseti/google/).

### Forseti Terraform Module Updates
The Terraform Forseti module has undergone a restructure to support flexible deployment scenarios.  If you have previously installed Forseti using Terraform, you can migrate your existing Terrafrom state by following the instructions in the [upgrade guide](/docs/latest/setup/upgrade.html) 


### Forseti on-GKE Enters Beta
We are excited to anounce that Forseti on-GKE is now released into Beta.  This is the result of considerable community collaboration over the last few months and we appreciate all who contributed to this effort.  There are several key features that make this feature robust, flexible, and secure:
* [Workload Identity](https://cloud.google.com/kubernetes-engine/docs/how-to/workload-identity) is a Beta feature in GKE which allows Kubernetes Service Accounts to be mapped to IAM Service Accounts in a GCP project.  This means that there is no need to generate IAM Service Account Keys to be deployed as Kubernetes Secrets, resulting in a simpler and more secure deployment.
* The [Config Validator chart](https://github.com/forseti-security/helm-charts/tree/master/charts/config-validator) is deployed as a Helm dependency of the Forseti Security chart.  The Config Validator uses [git-sync](https://github.com/kubernetes/git-sync) to periodically pull updated policies into the config-validator container.  This [policy-library](https://github.com/forseti-security/policy-library) can either be public or private and accessed over HTTPS or SSH.  Additionally, the Config Validator chart can be deployed independently of Forseti as a standalone service in GKE.



Please reach out to us on [Slack](https://forsetisecurity.slack.com/) or discuss@forsetisecurity.org with any questions.
