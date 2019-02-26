---
layout: default
title: About
---

# {{ page.title }}

Forseti Security is a collection of community-driven, open-source tools to help you improve the
security of your Google Cloud Platform (GCP) environments. Forseti consists of core modules that
you can enable, configure, and execute independently of each other. Community contributors are also
developing add-on modules to offer unique capabilities. Forseti’s core modules work together, and
provide a foundation that others can build upon.

Get started with
[Forseti Security]({% link _docs/latest/configure/general/index.md %}).

---

## When to use Forseti Security

Forseti Security makes sense when you need Security at Scale. It’s easy to monitor a few resources
in one or two projects, but at some point manual checking does not work anymore. If you want to
systematically monitor your GCP resources to ensure that access controls are set as you intended,
Forseti will allow creating rule-based policies to codify your security stance. Then, if something
changes unexpectedly, action will be taken including notifying you, and possibly automatically
reverting to a known state.

Taken as a whole, Forseti allows you to ensure your security is governed by consistent,
intelligible rules.

## How Forseti Security works

When you install Forseti Security, you deploy the core Forseti Security modules and configure them
to take a snapshot of your GCP resources, monitor those resources, and notify you of access policy
changes.

### [Inventory]({% link _docs/latest/configure/inventory/index.md %})

Inventory saves an inventory snapshot of your GCP resources to Cloud SQL, so you have a historical
record of what was in your cloud. With this, you can understand all the resources you have in GCP
and take action to conserve resources, reduce cost, and minimize security exposure. Inventory can
be configured to run as often as you want, and send email notifications when it updates your
resource snapshot

### [Scanner]({% link _docs/latest/configure/scanner/index.md %})

Scanner uses the information collected by Forseti Inventory to regularly compare role-based access
policies for your GCP resources. Scanner applies rules to audit GCP resources like the following:

  * Cloud Identity and Access Management (Cloud IAM) policies for Organizations,
    Folders, and Projects
  * Bucket ACLs
  * BigQuery dataset ACLs
  * Cloud SQL authorized networks

With Scanner, you can specify users, groups, and domains that are allowed, mandatory, or excluded
from resources and ensure that these access policies stay consistent. If it finds any access
policies that don’t match your Scanner rules, it can save those rule violations to Cloud SQL or to
Cloud Storage. This helps protect you against unsafe or unintentional changes.

### [Enforcer]({% link _docs/latest/use/cli/enforcer.md %})

Enforcer uses policies you create to compare the current state of your Compute Engine firewall to
the desired state. Enforcer is an on-demand command-line tool that compares policies in batch mode
over all managed projects or against selected projects. If it finds any differences in policy,
Enforcer uses Google Cloud APIs to make changes and displays the output of the results. Policies
can apply to individual projects or you can use an organization default policy.

The tool can also:

* Provide one-time enforcement of firewall policies on a single project
* Roll back firewall policies


### [Explain]({% link _docs/latest/use/cli/explain.md %})

The Explain add-on module provides visibility into your Cloud Identity and Access Management
(Cloud IAM) policies. Explain can help you understand:

* Who has access to what resources and how that user can interact with the resource
* Why a principal has permission on a resource, or why they don’t have a permission and how to fix
it
* What roles grant a permission and which roles aren’t in sync with recent changes

### [Email Notifications]({% link _docs/latest/configure/notifier/index.md %}#email-notifications)

When configured, Forseti Security can send email notifications for Inventory and Scanner using the
SendGrid API. SendGrid is currently the only supported email provider.
