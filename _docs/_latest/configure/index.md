---
title: Configure
order: 000
hide:
  right_sidebar: true
---

# {{ page.title }}

After you **[Set up Forseti]({% link _docs/latest/setup/index.md %})**,
use these guides to configure features.

---

| **[Configuring Forseti]({% link _docs/latest/configure/forseti/index.md %})** |
| :---------------------------------------------------------------------------- |
| Configure Forseti global and module-specific settings by updating the centrally-maintained configuration file. This includes basic configuration, and configuration for Inventory, Scanner, and Enforcer. |

| **[Configuring Inventory]({% link _docs/latest/configure/inventory/index.md %})** |
| :---------------------------------------------------------------------------- |
| Configure Inventory to collect and store information about your GCP resources. Inventory helps you undersand your resources and take action to conserve resources, reduce cost, and minimize security exposure. |

| **[Configuring Scanner]({% link _docs/latest/configure/scanner/index.md %})** |
| :---------------------------------------------------------------------------- |
| Configure Scanner to monitor your GCP resources for rule violations. Scanner uses the information from Inventory to regularly compare role-based access policies for your resources. |

| **[Configuring Enforcer]({% link _docs/latest/configure/enforcer/index.md %})** |
| :---------------------------------------------------------------------------- |
| Configure Enforcer to automatically correct policy discrepancies. Enforcer uses policies you create to compare the current state of your Compute Engine firewall to the desired state and uses Google Cloud APIs to make changes if it finds any differences. |

| **[Configuring Explain]({% link _docs/latest/configure/explain/index.md %})** |
| :---------------------------------------------------------------------------- |
| Configure Explain to help you understand, test, and develop Cloud Identity and Access Management (Cloud IAM) policies. |

| **[Enabling Email Notifications]({% link _docs/latest/configure/email-notification.md %})** |
| :---------------------------------------------------------------------------- |
| Enable Forseti email notifications using the SendGrid API. SendGrid is the suggested free email service provider for Google Cloud Platform (GCP). |

| **[Enabling G Suite Google Groups Collection]({% link _docs/latest/configure/gsuite-group-collection.md %})** |
| :---------------------------------------------------------------------------- |
| Enable the data collection of G Suite Google Groups for processing by Forseti Inventory. G Suite Groups Collection helps you make sure the right people are in the right group, and is required for Explain. |

