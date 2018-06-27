---
title: Best Practices
order: 002
---

# {{ page.title }}

This page includes best practices and rationale for using Forseti with specific
resources in your Google Cloud Platform (GCP) environments. Forseti is expanding
its ability to test these practices, and we appreciate your
[code contributions](https://github.com/GoogleCloudPlatform/forseti-security/blob/1.0-dev/.github/CONTRIBUTING.md)
to make this happen!

---

## Cloud Identity and Access Management (Cloud IAM) policies

**Don't use [primitive roles](https://cloud.google.com/iam/docs/understanding-roles#primitive_roles)
in Cloud IAM policies, and never grant primitive roles on an organization.**

Primitive roles give an identity a lot of power. By using custom roles, you apply the Principle of
Least Privilege and limit user access to only the resources they need.

**Don't grant an entire domain access to resources in a Cloud IAM policy.**


Granting access to an entire domain is usually too broad. Use groups to manage access instead.

**Protect your organization from external identities:**

* Don't give organization-level permissions to anyone outside your organization.
* Always use [custom roles](https://cloud.google.com/iam/docs/understanding-custom-roles) to
monitor all external identities in your organization.

Scanning for external identities helps stop untrusted users from getting access to your resources.

**Protect your resources from external identities:**

* Add external users to Cloud IAM policies as individual users. Don't add
* outside users to groups.

Using [Cloud IAM policies](https://cloud.google.com/iam/docs/resource-hierarchy-access-control),
you can audit external user activities and do lifecycle management.

**User Account Strategy**

Ensure all employees are using a [Cloud Identity Account](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_corporate_login_credentials).
This gives enterprise administrators full control over the lifecycle and
security policies of that user account, like deprovisioning when the user
leaves or enforcing two-step verification (2SV).

**Project Naming Convention**

Enterprises should agree on a standardised project naming convention. For
example [system name]-[environment (dev, test, uat, stage, prod)] =>
[costanalytics-dev](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#projects_are_identified_by_universally_unique_identifiers).
Some documents recommend using [company tag]-[group tag] prefixed to the above,
but this can cause project names to become stale too quickly as businesses
reorg. Consider moving this information to project
[labels](https://cloud.google.com/resource-manager/docs/creating-managing-labels#using_console).

**Group Naming Convention**

Groups are used to manage user membership in Cloud IAM policies. It's best to
use a consistent naming convention, like gcp-[system name]-[role type] =>
gcp-costanalytics-prodsupport, gcp-costanalytics-analysts

**Assign Roles to Groups**

[Assign project roles to groups of users](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#assign_project_roles_to_groups_of_users).
Instead of assigning individual user accounts roles in Cloud IAM, set up a
Group. Users can then request to join a group through an automated and
audited process to gain access to the GCP projects.

**Deeply Nested Sub Groups**

Using nested groups can help prevent inconsistency by repeating
the same configuration. Multiple levels of nested groups can delay
propagation of projects to users and make it difficult to find the
source of a user's access. It's best to limit nesting to one level.

**Organization Policy - Restricted Sharing Org Policy**

Restricted Sharing Org Policy provides the ability to prevent GCP resources from
being shared with identities outside their organization.

**Resource Management Hierarchy (GCP Project Structure)**

It's best to limit the complexity of the organization, folder, and project
hierarchy to solve specific requirements. For example, create one project per
system or application per environment (DEV, TEST, PROD). Use folders only if
distinct business users need autonomy to create projects and manage
organization policies in a separate GCP structure, or to have distinct
groupings of DEV, TEST, PROD with different folder-level policies for each
environment.

**Quota Management Process**

GCP provides default [quotas](https://cloud.google.com/compute/quotas) based on
a variety of factors. Your organization will need to monitor your quota usage
and apply for more quota when you're nearing your allocation limit.

**Remove Default Cloud IAM Organization Policies**

By default, a GCP organization is created allowing all users to create and
manage projects. For most large organizations, this should be removed.
Check the [default access control](https://cloud.google.com/resource-manager/docs/default-access-control).

**Consumer Account Strategy**

After a domain is registered with Google, there isn't any way to prevent
users from signing up for a consumer account with their organization account.
To mitigate risk, it's best to periodically review consumer accounts for
unmanaged users.

**Prevent Accidental Deletion**

You can place a
[lien](https://cloud.google.com/resource-manager/docs/project-liens) on a
project to block the project's deletion until you remove the lien. This can be
useful to protect projects of particular importance. 

**Ensure Cloud IAM Project Owners are Email Routable**

Google uses the members of the Cloud IAM role Project Owner to determine who
should receive GCP Outreach and Mass Service Announcement emails. If the member
of this role is not email routable, you could miss important notifications.
This is common for customers who use Cloud Identity and create
Google Groups that do not match mail routable groups in their mail system.
This is a risk if you use Cloud Identity and create Google Groups that don't
match mail-routable groups in your mail system. To prevent this, ensure that the
groups and the groups' members are mail-routable. 

**User and Group Provisioning Method**

You can provision users automatically using [Google Admin SDK's Directory
API](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#provision_users_to_googles_directory).
To ensure that access to GCP is consistent and stable when employees join
and leave the company, integrate the provisioning and management of users with
your organization's single source of truth for users, like Active Directory.

**Super Admin Access**

Because the G Suite Super Admin role has full administrative control in GCP,
it's best to review the role to ensure the appropriate people have access. For
more information, see [how to define domain administration
roles](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#define_domain_administration_roles).

**Organization Policy - VPC Service Controls**

VPC Service Controls enable security administrators to mitigate data
exfiltration risks via Google managed services such as Google Cloud Storage and
BigQuery. With VPC Service Controls, administrators can define a security
perimeter around resources of Google managed services to control communication
to and between those services.

**Third Party Access to GCP**

Third parties like vendors or contractors often need access to your GCP resources.
It's best to create a
[G Suite or Cloud Identity user account](https://support.google.com/cloudidentity/answer/7384684)
in your organization's Admin Console. This gives you full control over the user
account so that you can suspend or delete the identity to remove GCP access when
the third party leaves.

You can also use your own identity provider to enforce user authentication. To
allow separate configuration options, consider placing third party users in a
[separate organization unit](https://support.google.com/a/answer/182537).

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

For lower latency and disaster recovery, it's best to
[put certain resources in regions and zones](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#put_certain_resources_in_regions_and_zones_for_lower_latency_and_disaster_recovery).
Make sure you consider egress charges and whether it's critical for business
operations. It's common to provision a new VPC with subnetworks for the regions
you approve, and remove the default VPC that provides networks for all GCP
regions.

**DDoS Mitigation**

To minimize your attack surface, review and reduce the number of externally
facing resources. You should also consider using third-party DDoS protection
services.

**Consistent Naming Convention for Resources**

Use a consistent naming convention for typical resources like VPNs, firewalls,
rules, routes, subnetworks, and VMs.

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

It's best to have a separate Stackdriver account for each DEV, TEST, and PROD
environment. You can add projects to these Stackdriver accounts as monitored
projects. To allow independent management of Cloud IAM policies, initialize the
Stackdriver account in a separate project.

**Logging Retention**

Determine the enterprise requirements for retaining logging data. Implement a
policy for log data retention using
[object lifecycle management](https://cloud.google.com/storage/docs/lifecycle),
BiqQuery dataset
[table expiration](https://cloud.google.com/bigquery/docs/managing-datasets#table-expiration),
or as a custom solution.

**Logging Strategy**

Stackdriver is the default GCP logging tool. You might have a preferred logging
tool already, so you'll need to decide how Stackdriver will be used with, or in
place of, other logging tools. It's best to use Stackdriver Logging as a
[centralized location for logs in GCP](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_cloud_logging_as_a_centralized_location_for_logs).

**Monitoring Strategy**

Stackdriver is the default GCP monitoring tool. You might have a preferred
monitoring tool already, so you'll need to decide how Stackdriver will be used
with, or in place of, other monitoring tools. It's best to use Stackdriver
Monitoring to [monitor your resources and provide alerts](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_stackdriver_monitoring_to_monitor_your_resources_and_provide_alerts).

**Logging Exports**

[Export logs to BigQuery for analysis and long term storage](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#export_logs_to_bigquery_for_analysis_and_long_term_storage).

**Cloud Audit Logs**

Admin actions like creating, updating, and deleting a resource are captured in
the [Admin audit log](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#monitor_administrative_actions).
Requirements should be determined on retaining or alerting on these actions.

**Data Access Logs**

For more detailed access logs, you can enable [Data Access audit logs](https://cloud.google.com/logging/docs/audit/configure-data-access) that
capture read operations performed by users in a project.

**Aggregated Logging Exports**

You can create an [aggregated export](https://cloud.google.com/logging/docs/export/aggregated_exports)
that exports log entries from all of the projects, folders, and billing accounts
in an organization. For example, you could use this feature to export audit log
entries from your organization's projects to a central location.

## Cost Control

**Billing Alerts**

You can configure [billing alerts](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#set_alerts_for_monthly_spending_thresholds) to set a monthly
spending limit for a project or billing account. These alerts are sent only
to users with the Billing Admin role.

**Labels**

For more detailed cost attribution across resources or within or across
projects, you can use project
[labels](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_project_labels_to_further_categorize_projects_in_billing_export)
to further categorize projects in a billing export.

**Billing Admins**

You should review their current Billing Access Control following the principle
of least privilege. To learn more, see the [billing access overview](https://cloud.google.com/billing/docs/how-to/billing-access).

**Invoiced Billing Account**

If your organization is a large enterprise account, it's best to use an offline
billing account.

**Whitelisting the Customer Billing Account**

If your organization isn't on invoiced billing, you'll need to have your billing
account whitelisted by Google. This will prevent your account from being
automatically suspended or cancelled. Instead, Google Support will work with you
and the Google account team to whitelist the billing account and to ensure a
smooth process.

**Cost Attribution with Projects**

Projects are a good, standard way to attribute costs. If you use the recommended
[company tag]-[group tag]-[system name]-[env] convention, you can attribute
costs to a Business Unit > System > Environment level of granularity. The
monthly bill separates costs by project, then by resource type and labels. To
learn more, see the [enterprise guide](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#your_monthly_bill_breaks_down_costs_by_project_then_by_resource_type).

**Billing Exports**

To help get more detail from your monthly bill, you can set up a billing export
to get a [machine-readable version of your bill](https://cloud.google.com/docs/enterprise/best-practices-for-enterprise-organizations#use_billing_export_daily_to_get_a_machine-readable_version_of_your_bill).
