---
title: Configure
order: 001
hide:
  right_sidebar: true
---

# {{ page.title }}

After you **[set up Forseti Security]({% link _docs/v2.12/setup/index.md %})**,
use these guides to configure its features.

---

**[General configuration]({% link _docs/v2.12/configure/general/index.md %})**

Configure Forseti global and module-specific settings by updating the centrally-maintained
configuration file. This includes basic configuration, and configuration for Inventory, Scanner,
and Enforcer.

**[Configuring Inventory]({% link _docs/v2.12/configure/inventory/index.md %})**

Configure Inventory to collect and store information about your Google Cloud Platform (GCP) resources.
Inventory helps you understand your resources and take action to conserve resources, reduce cost, and
minimize security risk.

**[Configuring Scanner]({% link _docs/v2.12/configure/scanner/index.md %})**

Configure Scanner to monitor your GCP resources for rule violations. Scanner uses the information
from Inventory to regularly compare role-based access policies for your resources.

**[Configuring Notifier]({% link _docs/v2.12/configure/notifier/index.md %})**

Configure Notifier to dispatch a variety of messages through various channels and varying formats
alerting you to events in your environment.

**[Enabling G Suite data collection]({% link _docs/v2.12/configure/inventory/gsuite.md %})**

Enable the data collection of G Suite for processing by Forseti Inventory. G Suite access helps
ensure right people are in the right group, and is required for Forseti.
