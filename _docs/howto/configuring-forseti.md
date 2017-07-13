---
title: Configuring Forseti
order: 8
---

# {{ page.title }}

This page describes how to set up Forseti configurations. Forseti configurations
are global and module-specific settings such as the following:

-   `global`: configurations that are used by multiple modules such as database
    configurations.
-   `inventory`: configurations that are used only by Forseti Inventory, such as
    specifying the inventory pipelines to enable.
-   `scanner`: configurations that are used only by Forseti Scanner, such as
    specifying which scanners to enable.
-   `notifier`: configurations that are used only by Forseti Notifier, such as
    specifying which notifications to enable.

Configurations are centrally maintained in
forseti-security/configs/forseti_conf.yaml file that's organized into
module-specific sections. A single central file makes it easy to find and
maintain all the configurations.

## Setting up configurations

To set up your configuration, you'll edit
[forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
and save it as `forseti_conf.yaml`. For convenience, you can maintain different
versions of this file to support running different forseti instances.

-   `forseti_conf_prod.yaml`
-   `forseti_conf_staging.yaml`
-   `forseti_conf_john.yaml`
-   `forseti_conf_jane.yaml`

To specify the location of the configuration file for a module to read and use
at run-time, use the `--forseti_config` flag. Following is an example for
Forseti Inventory:

`forseti_inventory --forseti_config path/to/forseti_conf.yaml`

If you change a configuration such as by changing which pipeline or scanner to
run, you'll need to restart the appropriate module so it picks up the new
configuration change.

## What's next

-   Read about [configuring Inventory]({ % link _docs/quickstarts/inventory/#configuring-inventory %}).
