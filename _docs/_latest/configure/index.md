---
title: Configure
order: 001
hide:
  right_sidebar: true
---

# {{ page.title }}

After you **[Set up Forseti]({% link _docs/latest/setup/index.md %})**,
use these guides to configure features.

---

**[Configuring Forseti]({% link _docs/latest/configure/forseti/index.md %})**

Configure Forseti global and module-specific settings by updating the centrally-maintained
configuration file. This includes basic configuration, and configuration for Inventory, Scanner,
and Enforcer.

**[Configuring Inventory]({% link _docs/latest/configure/inventory/index.md %})**

Configure Inventory to collect and store information about your GCP resources. Inventory helps you
understand your resources and take action to conserve resources, reduce cost, and minimize security
exposure.

**[Configuring Scanner]({% link _docs/latest/configure/scanner/index.md %})**

Configure Scanner to monitor your GCP resources for rule violations. Scanner uses the information
from Inventory to regularly compare role-based access policies for your resources.

**[Configuring Notifier]({% link _docs/latest/configure/notifier/index.md %})**

Configuring Notifier to dispatch a variety of messages through various channels and varying formats 
alerting you to events in your environment.

**[Enabling G Suite data collection]({% link _docs/latest/configure/gsuite.md %})**

Enable the data collection of G Suite for processing by Forseti Inventory. G Suite
Groups Collection helps you make sure the right people are in the right group, and is required for
Forseti.
