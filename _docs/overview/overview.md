---
title: Forseti conceptual overview
order: 001
hide: 
  left_sidebar: true
---

# {{ page.title }}

Forseti Security is a collection of community-driven, open-source tools to help
you improve the security of your Google Cloud Platform (GCP) environments.
Forseti includes core modules that you can enable, configure, and execute
independently of each other. Community contributors can also develop add-on
modules to offer unique capabilities. Forseti's core modules work together to
provide their respective features, and provide a foundation that addons can
build upon.

Get started with
[Forseti Security]({% link _docs/quickstarts/forseti-security/index.md %}).

## When to use Forseti Security

Use Forseti Security when you want to monitor your GCP resources to ensure that
role-based access controls are set as you intended. Forseti Security can notify
you if policies change unexpectedly and work automatically to keep your access
policies in a known state. By using Forseti Security's modules together, you can
make sure that there isn't any unauthorized access to your GCP resources.

## How Forseti Security works

When you install Forseti Security, you can configure and deploy core Forseti
Security modules. The core Forseti Security modules work together to take a
snapshot of your GCP resources, monitor those resources, and notify you of
access policy changes.

![Forseti architecture diagram](/images/docs/overview/diagram.png)

### [Inventory]({% link _docs/quickstarts/inventory/index.md %})

Inventory saves an hourly snapshot of your GCP resources to Cloud SQL, so you
have a historical record of what was in your cloud. Using Inventory, you can
understand all the resources you have in GCP and take action to conserve
resources, reduce cost, and minimize security exposure. When configured,
Inventory can run on a custom basis and send email notifications when it updates
your resource snapshot.

### [Scanner]({% link _docs/quickstarts/scanner/index.md %})

Scanner uses the information collected by Forseti Inventory to regularly compare
role-based access policies for your GCP resources. Scanner applies rules to
audit the following resources in GCP:

  * Cloud Identity and Access Management (Cloud IAM) policies for Organizations,
    Folders, and Projects
  * Bucket ACLs
  * BigQuery dataset ACLs
  * Cloud SQL authorized networks

When you specify users, groups, and domains that are allowed, mandatory, or
excluded from resources, Scanner helps make sure your access policies stay
consistent. If it finds any access policies that don't match your Scanner Rules,
it saves those rule violations to Cloud SQL or, when configured, to a Google
Cloud Storage bucket. This helps protect you against unsafe or unintentional
changes. When configured, Scanner can send email notifications when it runs.

### [Enforcer]({% link _docs/quickstarts/enforcer/index.md %})

Enforcer uses policies you create to compare the current state of your Compute
Engine firewall to the desired state. Policies can apply to individual projects
or you can use an organization default policy. Enforcer is an on-demand
command-line tool that compares policies as a batch over all managed projects or
against one or more projects. If it finds any differences in policy, Enforcer
uses Google Cloud APIs to make changes and displays output of the results.

Following are some ways you might want to use Enforcer:

  * One-time enforcement of firewall policies on a single project.
  * Alert on changes to your expected firewall policy.
  * Roll back firewall policies if there's a problem.

### [Explain]({% link _docs/quickstarts/explain/index.md %})

Use an addon module like IAM Explain to understand your Cloud Identity and
Access Management (Cloud IAM) access policies in context of your groups and
resources. IAM Explain can help you understand the following:

Who has access to what resource and how that user can interact with the
resource. Why a principal has permission on a resource, or why they don't have a
permission and how to fix it. What roles grant a permission and which roles
aren't in sync with recent changes.

### [Email Notifications]({% link _docs/howto/configure/email-notification.md %})

When configured, Forseti Security can send email notifications for Inventory and
Scanner using the SendGrid API. SendGrid is currently the only supported email
provider.
