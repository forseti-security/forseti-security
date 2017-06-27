---
title: Inventory
order: 002
---
# {{ page.title }}

This quickstart describes how to get started with Forseti Inventory. Forseti
Inventory collects and stores information about your Google Cloud Platform
(GCP) resources. Forseti Security scans and Enforcer use Inventory data to
perform operations.

{% include _inventory/resources.md %}

## Executing the inventory loader

After you install Forseti, you can use the `forseti_inventory` command to
access the Inventory tool. If you installed Forseti in a virtualenv, activate
the virtualenv first.


To display Inventory flag options, run the following commands:

  ```bash
  $ forseti_inventory --helpshort
  ```

## Configuring Inventory pipelines to run
To run Forseti Inventory, you'll need a configuration file. Download
the [inventory_conf.yaml sample file](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/samples/inventory/inventory_conf.yaml)
, then run the command below to provide the configuration file to
`forseti_inventory`:

  ```bash
  $ forseti_inventory --config_path PATH_TO/inventory_conf.yaml
  ```

Forseti Inventory is now set up to run for your specified projects.