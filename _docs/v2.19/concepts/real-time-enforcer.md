---
title: Real-Time Enforcer
order: 005
---

# {{ page.title }}

{% include docs/v2.19/beta-release-feature.md %}

## Overview

Developed in partnership with [ClearDATA](https://www.cleardata.com/), Real-Time Enforcer 
automatically remediates non-compliant configurations in targeted Google Cloud Platform (GCP) resources.

Real-Time Enforcer uses a [Stackdriver log export](https://cloud.google.com/logging/docs/export/) 
that filters for Audit Log entries that create or update resources, and sends those log entries to a 
[Pub/Sub topic](https://cloud.google.com/pubsub/docs/overview). The `forseti-enforcer-gcp` service account 
is subscribed to that topic and evaluates each incoming log message and attempts to map it to a recognized resource. 
If it is recognized, Real-Time Enforcer will evaluate the resource against 
an [Open Policy Agent (OPA)](https://www.openpolicyagent.org/docs/) instance and remediate based on defined 
policies stored in a Cloud storage bucket.

Logs are written to Stackdriver in the same project that Real-Time Enforcer is running on, and can be found 
using the `Global` resource filter.

## The `cloud-foundation-forseti` Service Account

The `cloud-foundation-forseti` service account is used to set up the Real-Time Enforcer Terraform module.

### Permissions

For Real-Time Enforcer to work properly, the `cloud-foundation-forseti` service account 
requires the following permissions:

{% include docs/v2.19/cloud-foundation-forseti-enforcer-required-roles.md %}

## The `forseti-enforcer-gcp` Service Account

The `forseti-enforcer-gcp` service account gives Real-Time Enforcer application access to subscribe to the 
Pub/Sub subscription for messages, and access to modify resources for policy enforcement.

### Permissions

The `forseti-enforcer-gcp` service account requires the following permissions:

{% include docs/v2.19/forseti-enforcer-gcp-required-roles.md %}