---
title: About
---
# {{ page.title }}

Forseti Security is a community-driven collection of open source tools to
improve the security of your Google Cloud Platform (GCP) environments.

[Get Started]({% link _docs/quickstarts/forseti-security/index.md %}) with
Forseti Security.

## Forseti Security

Forseti's core modules come with every deployment of the tool. They can be
enabled, configured, and executed independently of each other. When deployed
these tmodules work together to provide their respective features.

**[Inventory]({% link _docs/quickstarts/inventory/index.md %})**

Takes a snapshot of resources on a recurring cadence, so you always have a
history of what was in your cloud.

**[Policy Scanner]({% link _docs/quickstarts/scanner/index.md %})**

Helps you monitor inventoried GCP resources like Cloud IAM,
BigQuery datasets, Cloud Storage bucket ACLs, and
[more]({% link _docs/quickstarts/inventory/index.md %}#google-cloud-platform-resource-coverage)
to ensure that role-based access controls are set as you intended, by
notifying you when specific policies change unexpectedly.

**[Policy Enforcer]({% link _docs/quickstarts/enforcer/index.md %})**

Works in an automated way to keep your access policies in a known state to
prevent unsafe changes.

## Addons 

Forseti's core modules provide the foundation for which addons can build upon.
These optional deployment modules offer their own unique capabilities.

**[IAM Explain]({% link _docs/quickstarts/explain/index.md %})**

Helps you to understand, test, and develop Cloud Identity and Access Management
(Cloud IAM) policies.
