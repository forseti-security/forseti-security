---
title: Best Practices 
order: 004
---
# {{ page.title }}

## Service Accounts
When you use multiple service accounts with your Forseti Security deployments,
you fulfill the security best practice of least privilege. Following are the
scenarios for which it's best to use separate service accounts:

 * **[Forseti Security Service Account](#forseti-security-service-account)**
 (required): Used by all core modules of the program to provide basic
 inventory, scanning, and enforcement actions.
 * **[GSuite Groups Service Account](#gsuite-groups-service-account)**
 (optional): Used to inventory GSuite Groups and their members.
 Forseti IAM explain requires this to be enabled.
 * **[Forseti Explain Service Account](#forseti-explain-service-account)**
 (optional): Used to provide IAM explain functionality.

When you name service accounts, it's best to use a descriptive name like
`forseti-security` or `forseti-security-gsuite`.

### Forseti Security Service Account
This service account is used by core modules of the Forseti service. For
example, `forseti_inventory` uses this service account to read and store the
supported resources. It's also used by `forseti_scanner` to scan
`forseti_inventory` records.

A good name for this service account would be `forseti-security`.

### GSuite Groups Service Account
It's best to use a separate service account for GSuite Groups inventory for
privilege separation because the service account key must be local to
`forseti_inventory`. By using a separate service account, the key scope is
limited to GSuite Groups if the machine is compromised.

If you [enable]{% link _docs/howto/gsuite-group-collection.md %})
GSuite Group inventory and create a service account, a good name
for the service account would be `forseti-security-gsuite-dwd`.

### Forseti Explain Service Account
You can use the Forseti Security Service account for IAM Explain. However,
since the `explain` service is an interactive tool and runs on its own GCE
instance, it's best to apply least privilege by creating a separate service
account for IAM Explain.

If you enable IAM Explain and create a service account, a good name for the
service account would be `forseti-security-iam-explain`.

## Service Account key security
Whether you install and deploy Forseti manually or by using the setup wizard,
you’ll need to store the keys securely. Google has
[published](https://cloudplatform.googleblog.com/2017/07/help-keep-your-Google-Cloud-service-account-keys-safe.html)
best practices on least privilege, secure storage, and rotation.

## Service Account permission explanation
It's important to know that if you don't plan to execute a particular piece of
Forseti, e.g. `forseti_enforcer` you don't need to create that service account
or grant those permissions.

Learn more about GCP IAM roles
[here](https://cloud.google.com/iam/docs/understanding-roles#predefined_roles).

### Service Account for Forseti Security
Forseti Security needs the following roles for `forseti_inventory` and/or
`forseti_scanner` purposes.

{% include _global/required-roles.md %}

### Service Account for GSuite Groups
To inventory GSuite Groups and their members, Forseti Security uses a service
account enabled for GSuite Domain Wide Delegation. The only permission this
service account needs is read-access on the Groups and Group Members services.

 * `https://www.googleapis.com/auth/admin.directory.group.readonly`
 
### Service Account for Forseti IAM Explain
Forseti Explain should have it's own Service account and it only requires access
to read from the inventory stored in CloudSQL.

**Granted on the project where Forseti Explain is deployed**

 * `roles/cloudsql.client`
