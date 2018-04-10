---
title: Forseti Service Accounts
order: 004
---
# {{ page.title }}

When you use multiple service accounts with your Forseti Security deployments,
you implement the security best practice of privilege separation. Following are
the scenarios for which it's best to use separate service accounts:

 * **[Forseti Security service account](#forseti-security-service-account)**
 (required): used by all core modules of the program to provide basic
 inventory, scanning, and enforcement actions.
 * **[G Suite Groups service account](#g-suite-groups-service-account)**
 (optional): used to inventory G Suite Groups and their members.
 Forseti Explain requires this to be enabled.
 * **[Explain service account](#explain-service-account)**
 (optional): used to provide Explain functionality.

When you name your service accounts, it's best to use a descriptive name like
`forseti-security` or `forseti-security-gsuite`.

The image below shows how different service accounts can work with
different modules and resources:

{% responsive_image path: images/docs/concepts/service-account-architecture.png alt: "service account architecture diagram" %}

### Forseti Security service account

This service account is used by core modules of the Forseti service. For
example, `forseti_inventory` uses this service account to read and store the
supported resources. It's also used by `forseti_scanner` to scan
`forseti_inventory` records.

A good name for this service account would be `forseti-security`.

### G Suite Groups service account

It's best to use a separate service account for G Suite Groups inventory for
privilege separation because the service account key must be local to
`forseti_inventory`. By using a separate service account, the key scope is
limited to G Suite Groups if the machine is compromised.

If you
[enable G Suite Group collection]({% link _docs/latest/configure/gsuite-group-collection.md %})
and create a service account, a good name for the service account would be
`forseti-security-gsuite-groups`.

### Explain service account

You can use the Forseti Security service account for Explain. However,
since the `explain` service is an interactive tool and runs on its own
Compute Engine instance, it's best to apply privilege separation principles
by creating a separate service account for Explain.

If you enable Explain and create a service account, a good name for the
service account would be `forseti-security-explain`.

## Service account key security

Whether you install and deploy Forseti manually or by using the setup wizard,
you'll need to store the keys securely. To learn how to keep your Google Cloud
Platform (GCP) service account keys safe, see these
[best practices](https://cloudplatform.googleblog.com/2017/07/help-keep-your-Google-Cloud-service-account-keys-safe.html)
on least privilege, secure storage, and rotation.

## Service account permissions

If you aren't using some Forseti modules, such as `forseti_enforcer`, you don't
need to create that service account or grant those permissions.

### Service account for Forseti Security

Forseti Security needs the following roles for `forseti_inventory` and
`forseti_scanner` purposes.

{% include docs/latest/required_roles.md %}

### Service account for G Suite Groups

To inventory G Suite Groups and their members, Forseti Security uses a service
account enabled for G Suite domain-wide delegation. The only permission this
service account needs is read-access on the Groups and Group Members services.

 * `https://www.googleapis.com/auth/admin.directory.group.readonly`
 
### Service account for Explain

Explain should have its own service account and it only requires access to read
from the inventory stored in Cloud SQL.

**Granted on the project where Explain is deployed**

 * `roles/cloudsql.client`
 
## What's next

 * Learn more about [Service Accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)
 * Read about how to [keep your GCP service account keys safe](https://cloudplatform.googleblog.com/2017/07/help-keep-your-Google-Cloud-service-account-keys-safe.html)
 * Learn about Cloud Identity and Access Management (Cloud IAM):
   * [Using Cloud IAM securely](https://cloud.google.com/iam/docs/using-iam-securely)
   * [Understanding Cloud IAM roles](https://cloud.google.com/iam/docs/understanding-roles)
