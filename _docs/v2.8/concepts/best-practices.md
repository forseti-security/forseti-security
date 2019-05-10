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

* Don't give organization-level permissions to anyone outside your organization.
* Always use [custom roles](https://cloud.google.com/iam/docs/understanding-custom-roles) to
     monitor all external identities in your organization.

Scanning for external identities helps stop untrusted users from getting access to your resources.

**Protect your resources from external identities:**

* Add external users to Cloud IAM policies as individual users.
* Don't add outside users to groups.

When you add external users directly to a Cloud IAM policy, it's easier to audit their activities
and do lifecycle management.

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
[health checking](https://cloud.google.com/load-balancing/docs/network/#health_checking).**

By limiting access from the internet, you prevent malicious external actors from bypassing policies
and getting access to the instance.

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