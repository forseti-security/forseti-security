---
title: When should I use Forseti vs. Security Health Analytics?
order: 3
---
{::options auto_ids="false" /}

It depends on your setup:

* If you want to be hands on, Forseti is a great solution to integrate into new or existing tooling.
* If you want to be more hands free, Security Health Analytics is a great solution for a managed service.

{: .table .table-striped}
|Forseti|Security Health Analytics|
|---|----|
|Customer deployed and managed|Fully managed by GCP with SLA|
|Community support|GCP support|
|[Customizable auditing]({% link _docs/latest/configure/scanner/rules.md %})|Comprehensive set of benchmarks (e.g. CIS certified)|
|Policy-as-code ecosystem (write the rules once, and re-use them everywhere in your workflow)|Managed rules added by GCP|
|[Real-time enforcement]({% link _docs/latest/configure/real-time-enforcer/default-policies.md %}) |Scanning only|
|Basic integration with CSCC|Deeper integrations with CSCC (reporting, dashboards, etc.)|

Both services can be integrated with Cloud Security Command Center (CSCC) to receive notifications.
Refer [here]({% link _docs/latest/configure/notifier/index.md %}#cloud-scc-notification) 
for setting up Forseti to use CSCC.
