---
title: Migrating Forseti Scanners to Rego Constraints
order: 800
---

# {{ page.title }}

This guide will walk through migrating the Python scanner rule files listed below to 
functionally equivalent Rego constraints found in the policy-library repository 
that can be used in Config Validator.

- Audit Logging
- Bigquery Dataset ACL
- Bucket ACL
- Cloud SQL
- Enabled APIs
- Firewall Rules
- Load Balancer Forwarding Rules
- IAM Policy
- Instance Network Interface
- Kubernetes Engine Version
- Kubernetes Engine
- KMS
- Location
- Retention Policy
- Role
- Service Account Key

**Note:** Config Validator currently ingests Cloud Asset Inventory (CAI) data only. 
GSuite data is not included in CAI exports. Users looking for GSuite specific constraints 
should continue to utilize the Forseti Python scanners.

For documentation on Config Validator and policy-library, refer [here]({% link _docs/latest/configure/config-validator/index.md %}).

{% include docs/latest/migrating-to-rego/audit-logging.md %}

{% include docs/latest/migrating-to-rego/bigquery-dataset-acl.md %}

{% include docs/latest/migrating-to-rego/bucket-acl.md %}

{% include docs/latest/migrating-to-rego/cloud-sql.md %}

{% include docs/latest/migrating-to-rego/enabled-apis.md %}

{% include docs/latest/migrating-to-rego/firewall-rules.md %}

{% include docs/latest/migrating-to-rego/iam-policy.md %}

{% include docs/latest/migrating-to-rego/instance-network-interface.md %}

{% include docs/latest/migrating-to-rego/kms.md %}

{% include docs/latest/migrating-to-rego/kubernetes-engine.md %}

{% include docs/latest/migrating-to-rego/kubernetes-engine-version.md %}

{% include docs/latest/migrating-to-rego/load-balancing-forwarding-rules.md %}

{% include docs/latest/migrating-to-rego/location.md %}

{% include docs/latest/migrating-to-rego/retention-policy.md %}

{% include docs/latest/migrating-to-rego/role.md %}

{% include docs/latest/migrating-to-rego/service-account-key.md %}