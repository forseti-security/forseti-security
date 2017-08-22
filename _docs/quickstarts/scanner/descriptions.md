---
title: Scanner Specifications
order: 102
---

# {{ page.title }}

This page describes the Forseti scanners that are available, how they work, and
why they're important. You can configure Scanner to execute multiple scanners in
the same run. Learn about [configuring
Scanner]({% link _docs/howto/configure/configuring-forseti.md %}#configuring-scanner).

Each scanner depends on one or more Forseti Inventory pipelines that must be set
to `enabled: true` in your `forseti_conf.yaml` file. Learn more about
[configuring
Inventory]({% link _docs/howto/configure/configuring-forseti.md %}#configuring-inventory).

## BigQuery dataset ACL scanner

BigQuery datasets have access properties that can publicly expose your datasets.
The BigQuery scanner supports a blacklist mode, to ensure unauthorized users
don't gain access to your datasets.

For examples of how to define scanner rules for your BigQuery datasets, see the
[bigquery_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/bigquery_rules.yaml)
rule file.

The bigquery scanner depends on the following Forseti Inventory pipelines:

- `load_bigquery_datasets_pipeline`

## Bucket ACL scanner

GCS buckets have ACLs that can grant public access to your GCS bucket and
objects. The bucket scanner supports a blacklist mode, to ensure unauthorized
users don't gain access to your GCS bucket.

For examples of how to define scanner rules for your GCS buckets, see the
[bucket_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/bucket_rules.yaml) rule file.

The bucket scanner depends on the following Forseti Inventory pipelines:

- `load_projects_buckets_pipeline`
- `load_projects_buckets_acls_pipeline`

## Cloud SQL Networks scanner

Cloud SQL instances can be configured to grant external networks access. The
Cloud SQL scanner supports a blacklist mode, to ensure unauthorized users don't
gain access to your Cloud SQL instances.

For examples of how to define scanner rules for your Cloud SQL instances, see
the
[cloudsql_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/cloudsql_rules.yaml)
rule file.

The cloudsql scanner depends on the following Forseti Inventory pipelines:

- `load_projects_cloudsql_pipeline`

## Load Balancer Forwarding Rules scanner

Load balancer forwarding rules can be configured to direct unauthorized external
traffic to your target instances. The forwarding rule scanner supports a
whitelist mode, to ensure each forwarding rule only directs to the intended
target instances.

For examples of how to define scanner rules for your forwarding rules, see the
[forwarding_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/forwarding_rules.yaml)
rule file.

The load balancer forwarding rule scanner depends on the following Forseti
Inventory pipelines:

- `load_forwarding_rules_pipeline`

## Groups scanner

Because groups can be added to IAM policies, GSuite group membership can allow
access on Google Cloud Platform. The group scanner supports a whitelist mode, to
make sure that only authorized users are members of your GSuite group.

For examples of how to define scanner rules for your GSuite groups, see the
[group_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/group_rules.yaml)
rule file.

The group scanner depends on the following Forseti Inventory pipelines:

- `load_groups_pipeline`
- `load_group_members_pipeline`

## IAM policy scanner (organization resources)

Cloud Identity and Access Management (Cloud IAM) policies directly grant access
on Google Cloud Platform. To ensure only authorized members and permissions are
granted in Cloud IAM policies, IAM scanner supports the following:

- Whitelist, blacklist, and required modes.
- Define whether the scope of the rule inherits from parents or just self.
- Access to specific organization, folder, or project resource types.

For examples of how to define scanner rules for IAM policies, see the
[iam_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/iam_rules.yaml)
rule file.

IAM scanner depends on the following Forseti Inventory pipelines:

- `load_orgs_pipeline`
- `load_org_iam_policies_pipeline`
- `load_folders_pipeline`
- `load_folder_iam_policies_pipeline`
- `load_projects_pipeline`
- `load_projects_iam_policies_pipeline`

## IAP scanner

Cloud Identity-Aware Proxy (Cloud IAP) enforces access control at the network
edge, inside the load balancer. If traffic can get directly to the VM, Cloud IAP
is unable to enforce its access control. The IAP scanner ensures that firewall
rules are properly configured and prevents the introduction of other network
paths that bypass the normal load balancer to instance flow.

For examples of how to define scanner rules for IAP, see the
[iap_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/iap_rules.yaml)
rule file.

IAP scanner depends on the following Forseti Inventory pipelines:

- `load_backend_services_pipeline`
- `load_firewall_rules_pipeline`
- `load_instance_group_managers_pipeline`
- `load_instance_groups_pipeline`
- `load_instance_templates_pipeline`
- `load_instances_pipeline`

## Network Interface scanner

Coming soon.

For examples of how to define scanner rules for network interfaces, see the
[instance_network_interface_rules.yaml](https://github.com/GoogleCloudPlatform/forseti-security/blob/dev/rules/instance_network_interface_rules.yaml)
rule file.
