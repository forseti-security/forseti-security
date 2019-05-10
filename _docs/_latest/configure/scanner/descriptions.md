---
title: Descriptions
order: 301
---

# {{ page.title }}

This page describes the Forseti scanners that are available, how they work, and
why they're important. You can
[configure Scanner]({% link _docs/latest/configure/scanner/index.md %}) to execute
multiple scanners in the same run.

---

## BigQuery dataset ACL scanner

BigQuery datasets have access properties that can publicly expose your datasets.
The BigQuery scanner supports blacklist and whitelist modes to ensure unauthorized users
don't gain access to your datasets, and only authorized users can gain access.

For examples of how to define scanner rules for your BigQuery datasets, see the
[`bigquery_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/bigquery_rules.yaml)
rule file.

## Blacklist scanner

Virtual Machine (VM) instances that have external IP addresses can communicate
with the outside world. If they are compromised, they could appear in various
blacklists and could be known as malicious, such as for sending spam,
hosting Command & Control servers, and so on. The blacklist scanner audits
all of the VM instances in your environment and determines if any VMs
with external IP addresses are on a specific blacklist you've configured.

For examples of how to define scanner rules, see the
[`blacklist_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/blacklist_rules.yaml) rule file.

## Bucket ACL scanner

Cloud Storage buckets have ACLs that can grant public access to your
Cloud Storage bucket and objects. The bucket scanner supports a blacklist mode,
to ensure unauthorized users don't gain access to your Cloud Storage bucket.

For examples of how to define scanner rules for your Cloud Storage buckets, see the
[`bucket_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/bucket_rules.yaml) rule file.

## Cloud Audit Logging scanner

You can configure Cloud Audit Logging to save Admin Activity and Data Access for
Google Cloud Platform (GCP) services. The audit log configurations for a project,
folder, or organization specify which logs should be saved, along with members who
are exempted from having their accesses logged. The audit logging scanner detects
if any projects are missing a required audit log, or have extra exempted members.

For examples of how to define scanner rules for Cloud Audit Logging, see the
[`audit_logging_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/audit_logging_rules.yaml)
rule file.

## Cloud SQL networks scanner

Cloud SQL instances can be configured to grant external networks access. The
Cloud SQL scanner supports a blacklist mode, to ensure unauthorized users don't
gain access to your Cloud SQL instances.

For examples of how to define scanner rules for your Cloud SQL instances, see
the
[`cloudsql_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/cloudsql_rules.yaml)
rule file.

## Config Validator scanner

The Config Validator scanner uses the [Forseti Config Validator](https://github.com/forseti-security/config-validator) 
service to evaluate violations with policies written in Rego. With this scanner 
in place, users are now able to define customized policies easily without writing 
a new scanner.

Read more about the Forseti Config Validator efforts and how to define customized 
policies for the Config Validator scanner [here](https://github.com/forseti-security/policy-library/blob/master/docs/user_guide.md).

## Enabled APIs scanner

The Enabled APIs scanner detects if a project has appropriate APIs enabled. It
supports whitelisting supported APIs, blacklisting unsupported APIs, and
specifying required APIs that must be enabled.

For examples of how to define scanner rules for Enabled APIs, see the
[`enabled_apis_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/enabled_apis_rules.yaml)
rule file.

## External Project Access Scanner

The External Project Access Scanner mitigates data exfiltration by identifying users who have access to projects outside of your organization or folder.

Each user in the inventory must be queried for their project access. The number of users in an organization will impact the execution time of this scanner.  It may therefore be undesirable to execute this scanner as frequently as other scanners.  By default, this scanner is not enabled in the Forseti server configuration.

This scanner is not part of the regular cron job, because it might take a long time to finish the scanning. To try it out you can manually run this scanner:
```
    forseti scanner run --scanner external_project_access_scanner
```

Before running this scanner, please 
[enable the service account with the required API scopes in your G Suite admin control panel]({% link _docs/latest/configure/inventory/gsuite.md %}#enable-the-service-account-in-your-g-suite-admin-control-panel).

## Firewall rules scanner

Network firewall rules protect your network & organization by only allowing
desired traffic into and out of your network. The firewall rules scanner can
ensure that all your network's firewalls are properly configured.

For examples of how to define scanner rules for your firewall rules scanner, see the
[`firewall_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/firewall_rules.yaml)
rule file.

## Groups scanner

Because groups can be added to Cloud Identity and Access Management (Cloud IAM)
policies, G Suite group membership can allow access on GCP. The group scanner
supports a whitelist mode, to make sure that only authorized users are members
of your G Suite group.

For examples of how to define scanner rules for your G Suite groups, see the
[`group_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/group_rules.yaml)
rule file.

## IAM policy scanner (organization resources)

Cloud IAM policies directly grant access on GCP. To ensure only authorized
members and permissions are granted in Cloud IAM policies, IAM policy scanner
supports the following:

* Whitelist, blacklist, and required modes.
* Define if the scope of the rule inherits from parents or just self.
* Access to specific organization, folder, project or bucket resource types.

For examples of how to define scanner rules for Cloud IAM policies, see the
[`iam_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/iam_rules.yaml)
rule file.

## IAP scanner

Cloud Identity-Aware Proxy (Cloud IAP) enforces access control at the network
edge, inside the load balancer. If traffic can get directly to the VM, Cloud IAP
is unable to enforce its access control. The IAP scanner ensures that firewall
rules are properly configured and prevents the introduction of other network
paths that bypass the normal load balancer to instance flow.

For examples of how to define scanner rules for Cloud IAP, see the
[`iap_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/iap_rules.yaml)
rule file.

## Instance network interface scanner

VM instances with external IP addresses expose your environment to an
additional attack surface area. The instance network interface scanner audits
all of your VM instances in your environment, and determines if any VMs with
external IP addresses are outside of the trusted networks.

For examples of how to define scanner rules for network interfaces, see the
[`instance_network_interface_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/instance_network_interface_rules.yaml)
rule file.

## KMS scanner

Alert or notify if the crypto keys in the organization are not rotated within the 
time specified. This scanner can ensure that all the cryptographic keys are 
properly configured. 

For examples of how to define scanner rules for your crypto keys, see the
[`kms_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/kms_rules.yaml)
rule file.

## Kubernetes Engine scanner

Kubernetes Engine clusters have a wide-variety of options.  You might
want to have standards so your clusters are deployed in a uniform
fashion.  Some of the options can introduce unnecessary security
risks.  The KE scanner allows you to write rules that check arbitrary
cluster properties for violations.  It supports the following
features:

* Any cluster property can be checked in a rule by providing a
  JMESPath expression that extracts the right fields.
  + See http://jmespath.org/ for a tutorial and detailed specifications.
* Rules can be whitelists or a blacklists.

You can find example rules in the
[`ke_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/ke_rules.yaml)
file.  The only rule enabled by default checks that logging is
enabled.  Check out some of the commented-out rules for more
advanced ideas.

This scanner is disabled by default, you can enable it in the
`scanner` section of your configuration file.

## Kubernetes Engine version scanner

Kubernetes Engine clusters running on older versions can be exposed to security
vulnerabilities, or lack of support. The KE version scanner can ensure your
Kubernetes Engine clusters are running safe and supported versions.

For examples of how to define scanner rules for your Kubernetes Engine versions, see the
[`ke_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/ke_rules.yaml)
file.

## Lien scanner
Allow customers to ensure projects do not get deleted, by ensuring Liens 
for their projects exist and are configured correctly.

For examples of how to define scanner rules for lien, see the
[`lien_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/lien_rules.yaml)
rule file.

## Load balancer forwarding rules scanner

You can configure load balancer forwarding rules to direct unauthorized external
traffic to your target instances. The forwarding rule scanner supports a
whitelist mode, to ensure each forwarding rule only directs to the intended
target instances.

For examples of how to define scanner rules for your forwarding rules, see the
[`forwarding_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/forwarding_rules.yaml)
rule file.

## Location scanner
Allow customers to ensure their resources are located only in the intended 
locations. Set guards around locations as part of automated project deployment.

For examples of how to define scanner rules for location, see the
[`location_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/location_rules.yaml)
rule file.

## Log sink scanner
Alert or notify if a project does not have required log sinks. This scanner will also 
be able to check if the sink destination is correctly configured.

For examples of how to define scanner rules for log sink, see the
[`log_sink_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/log_sink_rules.yaml)
rule file.

## Retention scanner

Allow customers to ensure the retention policies on their resources are set as intended.

For examples of how to define scanner rules for retention, see the ['retention_rules.yaml'](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/retention_rules.yaml) rule file.

## Service Account Key scanner

It's best to periodically rotate your user-managed service account
keys, in case the keys get compromised without your knowledge. With the
service account key scanner, you can define the max age at which your service
account keys should be rotated. The scanner will then find any key that is older
than the max age.

For examples of how to define scanner rules for your service account keys, see the
[`service_account_key_rules.yaml`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/rules/service_account_key_rules.yaml)
file.

