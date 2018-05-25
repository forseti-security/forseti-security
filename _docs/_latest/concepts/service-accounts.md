---
title: Service Accounts
order: 004
---

# {{ page.title }}

By default Forseti will create and use multiple service accounts in its default deployment. In 
doing this Forseti implements the security best practice of privilege separation and least
privilege.

Following are the service accounts Forseti creates on your behalf.

 * **[Forseti Security Server service account](#the-forseti-security-server-service-account)**
 * **[Forseti Security Client service account](#the-forseti-security-client-service-account)**
 
---

**The image below shows how the default service accounts created by Forseti are used.**

{% responsive_image path: images/docs/concepts/service-account-architecture.png alt: "service account architecture diagram" %}

## The Forseti Security Server service account 
The `forseti-security-server` service account is used by core modules of the Forseti service. For
example, Inventory uses this service account to read and store the supported resources. It's also
used by Scanner to audit policies.

The service account is used exclusively on the `forseti-security-server-vm` virtual machine
instance.

### Permissions 

For Forseti Security to work properly the `forseti-server` and subsequent `forseti-security-server`
account requires the following permissions

{% include docs/latest/forseti-security-server-required-roles.md %}

## The Forseti Security Client service account

The `forseti-security-client` service account has less access and is used exclusively on the
`forseti-security-client-vm` virtual machine.

This service account is used to communicate with the `forseti-security-server-vm`. Maintaining
this privilege separation is key to securing the granted rights of the `forseti-security-server-vm`
 and it's service account from that of the `forseti-security-client-vm` and its service account. 
 
 This way you can grant many people access to the `forseti-security-client-vm` without overgranting
 access to the APIs and roles required to Inventory, Audit, and Enforce.

### Permissions

should have its own service account and it only requires access to read
from the inventory stored in Cloud SQL.

{% include docs/latest/forseti-security-client-required-roles.md %}

## What's next

 * Learn more about [Service Accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)
 * Read about how to [keep your GCP service account keys safe](https://cloudplatform.googleblog.com/2017/07/help-keep-your-Google-Cloud-service-account-keys-safe.html)
 * Learn about Cloud Identity and Access Management (Cloud IAM):
   * [Using Cloud IAM securely](https://cloud.google.com/iam/docs/using-iam-securely)
   * [Understanding Cloud IAM roles](https://cloud.google.com/iam/docs/understanding-roles)
