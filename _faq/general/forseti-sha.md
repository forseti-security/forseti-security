---
title: When should I use Forseti vs. Security Health Analytics?
order: 3
---
{::options auto_ids="false" /}

It depends on your setup:

* If you want to be hands on, Forseti is a great solution to integrate into new or existing tooling.
* If you want to be more hands free, Security Health Analytics is a great solution for a managed service.

{: .table}
|Forseti|Security Health Analytics|
|--------|------------|
|Customer deployed and managed|Fully managed by GCP with SLA|
|Community support|GCP support|
|Customizable auditing for policy-as-code ecosystem|Comprehensive set of benchmarks (e.g. CIS certified)|
|Basic integration with CSCC|Deeper integrations with CSCC (reporting, dashboards, etc.)|

Both services can be integrated with Cloud Security Command Center (CSCC) to receive notifications.
Refer [here]({% link _docs/latest/configure/notifier/index.md %}#cloud-scc-notification) 
for setting up Forseti to use CSCC.