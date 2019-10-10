---
title: Service Accounts
order: 004
---

# {{ page.title }}

By default, Forseti will create and use multiple service accounts in its
default deployment. In doing this, Forseti implements the security best
practice of privilege separation and least privilege.

Following are the service accounts Forseti creates on your behalf.

 * **[Server service account](#the-server-service-account)**
 * **[Client service account](#the-client-service-account)**
 * **[Cloud Foundation service account](#the-cloud-foundation-service-account) (Terraform)**
 * **[Real-Time Enforcer service account](#the-real-time-enforcer-service-account) (optional)**

---

**The image below shows how the default service accounts created
by Forseti are used.**

{% responsive_image path: images/docs/concepts/service-account-architecture.png alt: "service account architecture diagram" %}

## The Server Service Account

The `forseti-server-gcp` service account has more access and is used
exclusively on the `forseti-server-vm` virtual machine instance.

This service account is used by core modules of the Forseti service. For
example, Inventory uses this service account to read and store the
supported resources. Scanner also uses the service account to audit policies.

### Permissions

For Forseti to work properly, the `forseti-server-gcp` service account
requires the following permissions:

{% include docs/v2.22/forseti-server-gcp-required-roles.md %}

## The Client Service Account

The `forseti-client-gcp` service account has less access and is used
exclusively on the `forseti-client-vm` virtual machine instance.

This service account is used to communicate with the
`forseti-server-vm`. The separation between service accounts is key to
securing the granted rights of the `forseti-server-gcp` service account
from that of the `forseti-client-gcp` service account.

By using separate service accounts, you can grant many users access to the
`forseti-client-vm` without over-granting access required for proper operation
of the core modules.

### Permissions

For Forseti to work properly, the `forseti-client-gcp` service account
requires the following permissions:

{% include docs/v2.22/forseti-client-gcp-required-roles.md %}

## The Cloud Foundation Service Account

The `cloud-foundation-forseti` service account is used to install Forseti through Terraform.

### Permissions

In order to install Forseti using Terraform, the `cloud-foundation-forseti` service account
requires the following permissions:

{% include docs/v2.22/cloud-foundation-forseti-required-roles.md %}

## The Real-Time Enforcer Service Account

The `forseti-enforcer-gcp` service account has specific permissions used for Real-Time Enforcer 
and is used exclusively on the `forseti-enforcer-vm` virtual machine instance.

### Permissions

For Real-Time Enforcer to work properly, the `forseti-enforcer-gcp` service account
requires the following permissions:

{% include docs/v2.22/forseti-enforcer-gcp-required-roles.md %}

## What's next

 * Learn more about [Service Accounts](https://cloud.google.com/iam/docs/understanding-service-accounts)
 * Read about how to [keep your Google Cloud service account keys safe](https://cloudplatform.googleblog.com/2017/07/help-keep-your-Google-Cloud-service-account-keys-safe.html)
 * Learn about Cloud Identity and Access Management (Cloud IAM):
   * [Using Cloud IAM securely](https://cloud.google.com/iam/docs/using-iam-securely)
   * [Understanding Cloud IAM roles](https://cloud.google.com/iam/docs/understanding-roles)
