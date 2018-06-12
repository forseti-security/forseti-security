---
title: Best Practices
order: 002
---

# {{ page.title }}

This page includes best practices and rationale for using Forseti with specific
resources in your Google Cloud Platform (GCP) environments. Future Forseti
releases are expected to include scans that correspond to each best practice,
so you can easily run them.

---

## Cloud Identity and Access Management (Cloud IAM) policies

**Don't use [primitive roles](https://cloud.google.com/iam/docs/understanding-roles#primitive_roles)
in Cloud IAM policies, and never grant primitive roles on an organization.**

Primitive roles give an identity a lot of power. By using custom roles, you apply the Principle of
Least Privilege and limit user access to only the resources they need.
    
**Don't grant an entire domain access to resources in a Cloud IAM policy.**

Granting access to an entire domain is usually too broad. Use groups to manage access instead. 
   
**Protect your organization from external identities:**

- Don't give organization-level permissions to anyone outside your organization.
- Always use [custom roles](https://cloud.google.com/iam/docs/understanding-custom-roles) to
     monitor all external identities in your organization.
 
Scanning for external identities helps stop untrusted users from getting access to your resources.

**Protect your resources from external identities:**

* Add external users to Cloud IAM policies as individual users.
* Don't add outside users to groups.

When you add external users directly to a Cloud IAM policy, it's easier to audit their activities
and do lifecycle management.

**User Account Strategy**

Ensure all employees are using a [Google Account from the enterprises Cloud
Identity](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_corporate_login_credentials).
This gives enterprise administrators full control over the lifecycle and
security policies of that user account; deprovision when user leaves, enforce
2SV, etc.

**Project Naming Convention**

Enterprises should agree on a standardised project naming convention. E.g.
[system name]-[environment (dev, test, uat, stage, prod)] =>
[costanalytics-dev](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#projects_are_identified_by_universally_unique_identifiers)
Some documents recommend using [company tag]-[group tag] prefixed to the above,
opinion today is that this means project names fall “out of date/stale” too
fast as companies go through reorgs. Consider moving this information to
project
[labels](https://cloud.google.com/resource-manager/docs/creating-managing-labels#using_console).

**Group Naming Convention**

Groups are used to manage user membership in IAM policies. A consistent naming
convention is recommended for enterprises. E.g. gcp-[system name]-[role type] =>
gcp-costanalytics-prodsupport, gcp-costanalytics-analysts

**Assign Roles to Groups**

[Assign project roles to groups of
users](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#assign_project_roles_to_groups_of_users).
Rather than assign individual user accounts roles in IAM, setup a Group. User
can then request to join a group (via their an automated and audited process)
to gain access to the GCP projects.

**Deeply Nested Sub Groups**

Nested groups can [DRY](https://en.wikipedia.org/wiki/Don%27t_repeat_yourself)
group memberships however they can be hard to reason about when determining
access. IAM Explain might help with this in the future. Deeply nested groups can
also delay the propagation of projects to users; as a best practice, one level
works best.

**Organization Policy - Restricted Sharing Org Policy**

Restricted Sharing Org Policy provides the ability to prevent GCP resources from
being shared with identities outside their organization.

**Resource Management Hierarchy (GCP Project Structure)**

Usage of the organization node, folders and projects should only have enough
complexity to solve specific requirements. A typical best practice is for a
customer to create a project per “system or application”, per “environment”
(DEV, TEST, PROD). Folders are only introduced if distinct business users
require autonomy (to create projects and manage Organization Policies) in their
own “space” in GCP or to have distinct groupings of DEV, TEST, PROD with
different policies applied at the folder level for each environment.

**Quota Management Process**

GCP provides default [quotas](https://cloud.google.com/compute/quotas) based on
an organization reputation on the platform.  Enterprises will need to define a
workflow to monitor their quota usage and to apply for more quota when they
determine that they are nearing their allocation.

**Remove Default IAM Organization Policies**

By default, a GCP organization is created allowing all users to create and
manage projects. For most large organizations, this should be removed.
Check the [default access control](https://cloud.google.com/resource-manager/docs/default-access-control).

**Consumer Account Strategy**

It is not possible to prevent users from signing up for a consumer account with
their work email once the domain is registered with Google, see b/65413695. To
mitigate, periodic review of consumer accounts is encouraged by checking the

**Prevent Accidental Deletion**

You can place a
[lien](https://cloud.google.com/resource-manager/docs/project-liens) upon a
project to block the project's deletion until you remove the lien. This can be
useful to protect projects of particular importance. 

**Ensure IAM Project Owners are Email Routable**

Google uses the members of the IAM role Project Owner to determine who should
receive GCP Outreach and Mass Service Announcement emails. If the member of this
role is not email routable, a customer may miss important notifications. This is
common for customers who use Cloud Identity and create Google Groups that do not
match mail routable groups in their mail system.

**User and Group Provisioning Method**

Google allows for the provisioning of users automatically via
[API](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#provision_users_to_googles_directory).
Enterprises should integrate the provisioning and management of users with
their enterprises single source of truth for users (e.g. AD) to ensure when
employees join and leave the company the state in Google is consistent.

**Super Admin Access**

The Super Admin role in G Suite has full administrative control in GCP, this
role should be reviewed to ensure the appropriate personnel have access.  Check
[how to define domain administration
roles](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#define_domain_administration_roles).

**Organization Policy - VPC Service Controls**

VPC Service Controls enable security administrators to mitigate data
exfiltration risks via Google managed services such as Google Cloud Storage and
BigQuery. With VPC Service Controls, administrators can define a security
perimeter around resources of Google managed services to control communication
to and between those services.

**Third Party Access to GCP**

Third parties (vendors, contractors) often require access to an enterprises
GCP, the recommended approach is to create a user account in the companies
Admin Console and assign the user account an appropriate license ([G Suite or
Cloud
Identity](https://support.google.com/cloudidentity/answer/7384684?hl=en)).
This solution gives the company full control over the user account, they can
then suspend or delete the identity when the third party leaves - removing
their access from GCP resources. The company can also use their identity
provider to enforce user authentication. To allow for separate configuration
options, they could also consider placing these users in a [separate
organization unit](https://support.google.com/a/answer/182537?hl=en).

## Service accounts

**Don't use default service accounts. They have
[primitive roles](https://cloud.google.com/iam/docs/understanding-roles#primitive_roles).**

By using custom roles, you apply the Principle of Least Privilege and limit service account access
to only the resources they need.

**Don't let your service accounts have more than two active keys.**

By limiting the number of active keys, you apply the Principle of Least Privilege and limit the
number of accounts that have powerful access.

**Rotate keys every 180 days and notify when service account keys are older than 180 days.**

There is currently no way to audit for use of a key. By rotating keys regularly, you help prevent
use of a key that could be compromised.

## Cloud Storage

**Don't use any [legacy bucket roles](https://cloud.google.com/storage/docs/access-control/iam#acls)
on your Cloud Storage buckets.**

Legacy bucket roles are usually too broad. Use Cloud IAM roles to give users only the access they
need.

**Don't allow buckets to be publicly visible. It's best to keep data private in general.**

By keeping data private, you prevent malicious external actors from uploading content that could
get ingested into an application or replace data in the bucket.

## Compute Engine

**Minimize direct exposure to the internet. Don't open up 0.0.0.0/0.**

By limiting exposure to the internet, you prevent malicious external actors from getting access to
the instance.

## Networking

**Don't allow instances behind backend services to be directly accessed from the internet.
Allow access only from specified ranges for
[health checking](https://cloud.google.com/compute/docs/load-balancing/network/#health_checking).**

By limiting access from the internet, you prevent malicious external actors from bypassing policies
and getting access to the instance.

**Regions and Zones**

It is recommended that the customer [put certain resources in regions and zones
for lower latency and disaster
recovery](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#put_certain_resources_in_regions_and_zones_for_lower_latency_and_disaster_recovery),
however care must be taken when considering egress charges and whether this is
critical for business operations.  A typical practice is to provision a new VPC
with subnetworks for the regions that an enterprise approves, removing the
default VPC that provides subnetworks for all GCP regions.

**Security Scanning**

[Scan for common website
vulnerabilities](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#scan_for_common_website_vulnerabilities)
where applicable. These must be supplemented with manual security reviews.
Third-party penetration and security testing should be considered.

**DDoS Mitigation**

The attack surface should be reviewed and minimised by reducing the number of
externally facing resources. Consider the use of third-party DDoS protection
services. 

**Consistent Naming Convention for Resources**

Determine a consistent naming convention for typical resources: VPNs, Firewall
Rules, Subnets, Routes, VMs, etc.

## BigQuery

**It's best to keep data private in general:**

* Don't allow datasets to be publicly readable or writable.
* Don't share datasets with outside entities.

By limiting access to datasets, you prevent malicious external actors from changing or adding data.

## Cloud SQL

**Create a [root password](https://cloud.google.com/sql/docs/mysql/create-manage-users#user-root)
for database users.**

Adding a password to the root user provides the most basic protection.

**Always access Cloud SQL through
[Cloud SQL Proxy](https://cloud.google.com/sql/docs/mysql/sql-proxy).**

Cloud SQL Proxy offers secure connections and handles authentication, so you don't have to
whitelist IP addresses.

**Always use SSL connections if you are not using Cloud SQL Proxy or if you configured
authorized networks.**

By using SSL connections, you prevent third parties from seeing the data that's transferred
between client and server over insecure networks.

## Event Logging and Resource Monitoring

**Stackdriver Account per Environment**

Best practice is to have a Stackdriver account per environment (DEV, TEST, &
PROD). Projects can be added to these Stackdriver accounts as a Monitored
project. It is recommended to initialize the Stackdriver account in a separate
project - to allow for independent management of the IAM policies.

**Logging Retention**

Determine the enterprise requirements for retaining logging data. This will
need to be implemented as an object [lifecycle policy for
GCS](https://cloud.google.com/storage/docs/lifecycle), a dataset table
[expiration
time](https://cloud.google.com/bigquery/docs/managing-datasets#table-expiration)
for BigQuery, or as a custom solution.

**Logging Strategy**

Stackdriver is the default logging tool in GCP. Enterprise customers usually
have a preferred logging tool. It should be determined how Stackdriver will be
used in conjunction with or in place of other logging tools. Best practice is
to use Stackdriver Logging as a [centralized location for logs in
GCP](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_cloud_logging_as_a_centralized_location_for_logs).

**Monitoring Strategy**

Stackdriver is the default monitoring tool in GCP. Enterprise customers usually
have a preferred monitoring tool. It should be determined how Stackdriver will
be used in conjunction with
[partners](https://cloud.google.com/stackdriver/partners) or in place of other
monitoring tools. Best practice is to [use Stackdriver Monitoring to monitor
your resources and provide
alerts](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_stackdriver_monitoring_to_monitor_your_resources_and_provide_alerts).

**Logging Exports**

[Export logs to BigQuery for analysis and long term
storage](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#export_logs_to_bigquery_for_analysis_and_long_term_storage).

**Cloud Audit Logs**

[Admin actions, such as creating, updating, and deleting a resource are
captured in the Cloud Audit
Logs](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#monitor_administrative_actions).
Requirements should be determined on retaining or alerting on these actions.

**Data Access Logs**

For finer grained access logs, [Data Access logs can be
enabled](https://cloud.google.com/logging/docs/audit/configure-data-access) to
capture read operations being performed by users in the project.

**Aggregated Logging Exports**

An organization can create an [aggregated
export](https://cloud.google.com/logging/docs/export/aggregated_exports) sink
that can export log entries from all the projects, folders, and billing
accounts of the organization. As an example, an organization might use this
feature to export audit log entries from its projects to a central location.

## Cost Control

**Billing Alerts**

[Billing
alerts](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#set_alerts_for_monthly_spending_thresholds)
can be configured for a project or a billing account for monthly spending
thresholds. There is a limitation that these alerts will only go to the Billing
Admin.

**Labels**

For finer grained cost attribution across resources within or across projects
project
[labels](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_project_labels_to_further_categorize_projects_in_billing_export)
can be used to further categorize projects in the billing export.

**Billing Admins**

Organizations should review their current Billing Access Control following the
principle of least privilege.
Check [how to bill](https://cloud.google.com/billing/docs/how-to/billing-access).

**Invoiced Billing Account**

Most large enterprise accounts should be using an offline billing account.

**Whitelisting the Customer Billing Account**

For large customers not on invoiced billing, their billing account should be
whitelisted by Google. This will prevent their account from being suspended or
cancelled automatically - instead Google support will reach out to the Google
account team and the customer before taking action.

**Cost Attribution with Projects**

Projects are a good standard way of attributing costs. If the naming convention
of a project follows the recommended [company tag]-[group tag]-[system
name]-[env].The enterprise can attribute costs to a Business Unit > System >
Environment level of granularity. [The monthly bill breaks down costs by
project, then by resource type and
labels](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#your_monthly_bill_breaks_down_costs_by_project_then_by_resource_type).

**Billing Exports**

For better ability to interrogate the monthly bill, consider setting up a
billing export to get a [machine-readable version of your
bill](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_billing_export_daily_to_get_a_machine-readable_version_of_your_bill).

**Multiple Billing Accounts**

Some large customers require multiple billing accounts as the above suggested
internal chargeback process is insufficient for their needs. Multiple billing
accounts is possible, but has caveats.

