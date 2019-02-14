---
title: Inventory
order: 101
---

# {{ page.title }}

Forseti Inventory collects and stores information about your Google
Cloud Platform (GCP) resources. Inventory data is
[transformed to a data model]({% link _docs/v2.11/concepts/models.md %})
that Forseti Scanner and Explain use to perform their operations.

---

## Before you begin

Before you start using Inventory, make sure that Inventory is
[configured]({% link _docs/v2.11/configure/inventory/index.md %}) and the
proper [GCP]({% link _docs/v2.11/concepts/service-accounts.md %}) and
[G Suite]({% link _docs/v2.11/configure/inventory/gsuite.md %}) acccess is set up
for your Forseti GCP service account.

## Running Inventory

To display Inventory flag options, run `forseti inventory -h`.

### Create a new inventory

To start a new inventory process, run the following command:

```bash
forseti inventory create
```

You can track the status by using the `list` command.

### Create a new inventory and data model

Because the data model is widely used in Forseti, it can be helpful to create
the data model along with the newest inventory.

```bash
forseti inventory create --import_as <MODEL_NAME>
```

### List all the existing inventories

To list all of the existing inventories and their statuses, run the following command:

```bash
forseti inventory list
```

### Get an inventory

To display a summary of an inventory, run the following command:

```bash
forseti inventory get <INVENTORY_INDEX_ID>
```

To get the `<INVENTORY_INDEX_ID>`, run the `list` command.

### Delete an inventory

To delete an inventory, run the following command:

```bash
forseti inventory delete <INVENTORY_INDEX_ID>
```

### Purge inventories

To delete all inventories that are older than a specific date, run the following command:

```bash
forseti inventory purge <RETENTION_DAY>
```

Note that `<RETENTION_DAY>` is the number of days to retain the data. If you don't specify
a value, then the value in `forseti_config.yaml` will be used.


## What's next
* Learn about [configuring Inventory]({% link _docs/v2.11/configure/inventory/index.md %}).
