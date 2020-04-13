---
title: Configure
order: 001
hide:
  right_sidebar: true
---

# {{ page.title }}

After you **[set up Forseti Security]({% link _docs/latest/setup/index.md %})**,
use these guides to configure its features.

---

**[General configuration]({% link _docs/latest/configure/general/index.md %})**

Configure Forseti global and module-specific settings by updating the centrally-maintained
configuration file. This includes basic configuration, and configuration for Inventory, Scanner,
and Enforcer.

**[Configuring Inventory]({% link _docs/latest/configure/inventory/index.md %})**

Configure Inventory to collect and store information about your Google Cloud Platform (GCP) resources.
Inventory helps you understand your resources and take action to conserve resources, reduce cost, and
minimize security risk.

**[Configuring Scanner]({% link _docs/latest/configure/scanner/index.md %})**

Configure Scanner to monitor your GCP resources for rule violations. Scanner uses the information
from Inventory to regularly compare role-based access policies for your resources.

**[Configuring Notifier]({% link _docs/latest/configure/notifier/index.md %})**

Configure Notifier to dispatch a variety of messages through various channels and varying formats
alerting you to events in your environment.

**[Configuring Real-Time Enforcer]({% link _docs/latest/configure/real-time-enforcer/index.md %})**

Configure Real-Time Enforcer to automatically remediate non-compliant configurations in targeted 
Google Cloud Platform (GCP) resources.

**[Configuring Cloud Profiler]({% link _docs/latest/configure/cloud-profiler/index.md %})**

Configure Cloud Profiler to view and analyze CPU usage and memory-allocation of your Forseti application on a 
Google Cloud Platform (GCP) interface.

**[Configuring Forseti Visualizer](https://github.com/forseti-security/forseti-visualizer)**

Configure Forseti Visualizer to better understand your GCP organization
structure, and to gain insights into policy adherence through identification
of violations.

**[Enabling G Suite data collection]({% link _docs/latest/configure/inventory/gsuite.md %})**

Enable the data collection of G Suite for processing by Forseti Inventory. G Suite access helps
ensure right people are in the right group, and is required for Forseti.

**[Configuring Config Validator]({% link _docs/latest/configure/config-validator/index.md %})**

Configure Config Validator Scanner to scan for non-compliant resources in your
Google Cloud Platform (GCP) infrastructure.

**[Migrating Python Scanners to Rego Constraints]({% link _docs/latest/configure/migrating-to-rego/index.md %})**

Migrate current Forseti scanners to Rego constraints for use by Config Validator Scanner.