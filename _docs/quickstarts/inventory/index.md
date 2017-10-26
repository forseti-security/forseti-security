---
title: Inventory
order: 002
---
# {{ page.title }}

This quickstart describes how to get started with Forseti Inventory. Forseti
Inventory collects and stores information about your Google Cloud Platform
(GCP) resources. Forseti Scanner and Enforcer use Inventory data to
perform operations.

{% include docs/resources.md %}

## Executing the inventory loader

After you install Forseti, you can use the `forseti_inventory` command to
run the Inventory tool. If you installed Forseti in a virtualenv, activate
the virtualenv first.


To display Inventory flag options, run the following commands:

  ```bash
  forseti_inventory --helpshort
  ```

## Configuring Inventory

{% include docs/howto/min_conf_settings.md %}

## What's next
- Learn more about [configuring Forseti]({% link _docs/howto/configure/configuring-forseti.md %}).
