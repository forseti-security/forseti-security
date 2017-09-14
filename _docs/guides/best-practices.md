---
title: Best Practices 
order: 004
---
# {{ page.title }}

## Service accounts
When you use multiple service accounts with your Forseti Security deployments,
you implement the security best practice of privilege separation. Following are the
scenarios for which it's best to use separate service accounts:

 * **[Forseti Security service account](#forseti-security-service-account)**
 (required): Used by all core modules of the program to provide basic
 inventory, scanning, and enforcement actions.
 * **[GSuite Groups service account](#gsuite-groups-service-account)**
 (optional): Used to inventory GSuite Groups and their members.
 Forseti IAM Explain requires this to be enabled.
 * **[Forseti Explain service account](#forseti-explain-service-account)**
 (optional): Used to provide IAM Explain functionality.

When naming service accounts, it's best to use a descriptive name like
`forseti-security` or `forseti-security-gsuite`.

### Forseti Security service account
This service account is used by core modules of the Forseti service. For
example, `forseti_inventory` uses this service account to read and store the
supported resources. It's also used by `forseti_scanner` to scan
`forseti_inventory` records.

A good name for this service account would be `forseti-security`.

### GSuite Groups service account
It's best to use a separate service account for GSuite Groups inventory for
privilege separation because the service account key must be local to
`forseti_inventory`. By using a separate service account, the key scope is
limited to GSuite Groups if the machine is compromised.

If you [enable]({% link _docs/howto/configure/gsuite-group-collection.md %})
GSuite Group inventory and create a service account, a good name
for the service account would be `forseti-security-gsuite-groups`.

### Forseti Explain service account
You can use the Forseti Security service account for IAM Explain. However,
since the `explain` service is an interactive tool and runs on its own
Compute Engine instance, it's best to apply privilege separation principles
by creating a separate service account for IAM Explain.

If you enable IAM Explain and create a service account, a good name for the
service account would be `forseti-security-iam-explain`.

## Service account key security
Whether you install and deploy Forseti manually or by using the setup wizard,
you'll need to store the keys securely. Google has
[published](https://cloudplatform.googleblog.com/2017/07/help-keep-your-Google-Cloud-service-account-keys-safe.html)
best practices on least privilege, secure storage, and rotation.

## Service account permission explanation
It's important to know that if you don't plan to execute a particular piece of
Forseti, such as `forseti_enforcer`, you don't need to create that service account
or grant those permissions.

* Learn more about [GCP IAM roles](https://cloud.google.com/iam/docs/understanding-roles#predefined_roles).
* Learn more about [Using IAM securely](https://cloud.google.com/iam/docs/using-iam-securely).

### Service account for Forseti Security
Forseti Security needs the following roles for `forseti_inventory` and/or
`forseti_scanner` purposes.

{% include docs/required_roles.md %}

### Service account for GSuite Groups
To inventory GSuite Groups and their members, Forseti Security uses a service
account enabled for GSuite domain-wide delegation. The only permission this
service account needs is read-access on the Groups and Group Members services.

 * `https://www.googleapis.com/auth/admin.directory.group.readonly`
 
### Service account for Forseti IAM Explain
Forseti Explain should have its own service account and it only requires access
to read from the inventory stored in Cloud SQL.

**Granted on the project where Forseti Explain is deployed**

 * `roles/cloudsql.client`
 
