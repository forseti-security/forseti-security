---
title: Inventory
order: 002
---
# {{ page.title }}

This quickstart describes how to get started with Forseti Inventory. Forseti
Inventory collects and stores information about your Google Cloud Platform
(GCP) resources. Forseti Scanner and Enforcer use Inventory data to
perform operations.

{% include _inventory/resources.md %}

## Executing the inventory loader

After you install Forseti, you can use the `forseti_inventory` command to
run the Inventory tool. If you installed Forseti in a virtualenv, activate
the virtualenv first.


To display Inventory flag options, run the following commands:

  ```bash
  forseti_inventory --helpshort
  ```

## Configuring Inventory
To run Forseti Inventory, you'll need to setup your configuration file. Edit
the [forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
file and save it as **forseti_conf.yaml**.

You will also need to edit, at a minimum, the following variables in the config file:

* db_host
* db_user
* db_name

To run Forseti Inventory, execute the command below, providing the configuration file to
`forseti_inventory`:

  ```bash
  forseti_inventory --config_path path/to/forseti_conf.yaml
  ```

Forseti Inventory is now set up to run for your specified projects.

## What's next
- Learn more about [configuring Forseti]({% link _docs/howto/configuring-forseti.md %})
