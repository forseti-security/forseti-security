---
title: Forseti Configuration
order: 104
---

# {{ page.title }}

This page lists the steps to configure Forseti further after installation.

---

## **Forseti Configuration**

Now that Forseti has been deployed, there are additional steps that you can follow to further 
[configure Forseti]({% link _docs/latest/configure/index.md %}). Some of the commonly used features are 
listed below:

- [Enable G Suite Scanning]({% link _docs/latest/configure/inventory/gsuite.md %})
- [Enable Cloud Security Command Center Notifications]({% link _docs/latest/configure/notifier/index.md %}#cloud-scc-notification)
  - After activating this integration, add the Source ID into the Terraform configuration using 
  the `cscc_source_id` input and re-run the Terraform `apply` command.
