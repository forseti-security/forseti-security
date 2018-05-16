---
title: Scanner Specifications
order: 102
---

# {{ page.title }}

This page describes the Forseti scanners that are available, how they work, and
why they're important. You can configure Scanner to execute multiple scanners in
the same run. Learn about [configuring Scanner]({% link _docs/latest/configure/scanner/index.md %}).

## BigQuery dataset ACL scanner

BigQuery datasets have access properties that can publicly expose your datasets.
The BigQuery scanner supports a blacklist mode, to ensure unauthorized users
don't gain access to your datasets.

For examples of how to define scanner rules for your BigQuery datasets, see the
[`bigquery_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/bigquery_rules.yaml)
rule file.

## Blacklist scanner

Virtual Machine (VM instances) that have external IP addresses can communicate
with the outside world. If they are compromised, they could appear in various 
blacklists and could be known as malicious, such as for sending spam, 
hosting Command & Control servers, and so on. The blacklist scanner audits
all of the VM instances in your environment and determines if any VMs
with external IP addresses are on a specific blacklist you've configured.

For examples of how to define scanner rules, see the
[`blacklist_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/blacklist_rules.yaml) rule file.

## Bucket ACL scanner

Cloud Storage buckets have ACLs that can grant public access to your 
Cloud Storage bucket and objects. The bucket scanner supports a blacklist mode, 
to ensure unauthorized users don't gain access to your Cloud Storage bucket.

For examples of how to define scanner rules for your Cloud Storage buckets, see the
[`bucket_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/bucket_rules.yaml) rule file.

## Cloud Audit Logging scanner

Cloud Audit Logging can be configured to save Admin Activity and Data Access for
GCP services. The audit log configurations for a project, folder or organization
specify which logs should be saved along with members who are exempted from
having their accesses logged. The audit logging scanner detects if any projects
are missing a required audit log, or have extra exempted members.

For examples of how to define scanner rules for Cloud Audit Logging, see the
[audit_logging_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/audit_logging_rules.yaml)
rule file.

## Cloud SQL Networks scanner

Cloud SQL instances can be configured to grant external networks access. The
Cloud SQL scanner supports a blacklist mode, to ensure unauthorized users don't
gain access to your Cloud SQL instances.

For examples of how to define scanner rules for your Cloud SQL instances, see
the
[`cloudsql_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/cloudsql_rules.yaml)
rule file.

## Enabled APIs scanner

The Enabled APIs scanner detects that a project has appropriate APIs enabled. It
supports whitelisting supported APIs, blacklisting unsupported APIs, and
specifying required APIs that must be enabled.

For examples of how to define scanner rules for Enabled APIs, see the
[enabled_apis_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/enabled_apis_rules.yaml)
rule file.

## Firewall Rules scanner

Network firewall rules protects your network & organization by only allowing 
desired traffic into and out of your network. The firewall rules scanner can 
ensure that all your network's firewalls are properly configured.

For examples of how to define scanner rules for your firewall rules scanner, see the
[`firewall_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/firewall_rules.yaml)
rule file.

## Load Balancer Forwarding Rules scanner

Load balancer forwarding rules can be configured to direct unauthorized external
traffic to your target instances. The forwarding rule scanner supports a
whitelist mode, to ensure each forwarding rule only directs to the intended
target instances.

For examples of how to define scanner rules for your forwarding rules, see the
[`forwarding_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/forwarding_rules.yaml)
rule file.

## Groups scanner

Because groups can be added to Cloud Identity and Access Management (Cloud IAM)
policies, G Suite group membership can allow access on Google Cloud Platform (GCP).
The group scanner supports a whitelist mode, to make sure that only authorized
users are members of your G Suite group.

For examples of how to define scanner rules for your G Suite groups, see the
[`group_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/group_rules.yaml)
rule file.

## IAM policy scanner (organization resources)

Cloud IAM policies directly grant access on GCP. To ensure only authorized
members and permissions are granted in Cloud IAM policies, IAM policy scanner
supports the following:

 - Whitelist, blacklist, and required modes.
 - Define if the scope of the rule inherits from parents or just self.
 - Access to specific organization, folder, or project resource types.

For examples of how to define scanner rules for Cloud IAM policies, see the
[`iam_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/iam_rules.yaml)
rule file.

## IAP scanner

Cloud Identity-Aware Proxy (Cloud IAP) enforces access control at the network
edge, inside the load balancer. If traffic can get directly to the VM, Cloud IAP
is unable to enforce its access control. The IAP scanner ensures that firewall
rules are properly configured and prevents the introduction of other network
paths that bypass the normal load balancer to instance flow.

For examples of how to define scanner rules for Cloud IAP, see the
[`iap_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/iap_rules.yaml)
rule file.

## Instance Network Interface scanner

VM instances with external IP addresses expose your environment to an
additional attack surface area. The instance network interface scanner audits
all your VM instances in your environment, and determines if any VMs with
external IP addresses are outside of the trusted networks.

For examples of how to define scanner rules for network interfaces, see the 
[`instance_network_interface_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/instance_network_interface_rules.yaml)
rule file.

## Kubernetes Engine Version scanner

Kubernetes Engine clusters running on older versions can be exposed to security 
vulnerabilities, or lack of support.  The KE version scanner can ensure your 
Kubernetes Engine clusters are running safe and supported versions.

For examples of how to define scanner rules for your Kubernetes Engine versions, see the
[`ke_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/rules/ke_rules.yaml)
file.
