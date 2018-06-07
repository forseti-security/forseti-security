---
title: Inventory
order: 002
---

# {{ page.title }}

Forseti Inventory collects and stores information about your Google Cloud Platform (GCP)
resources. The Inventory data is transformed to data model that is used
by Forseti Scanner and Explainer to perform operations.

---

## Running Inventory

Before you start using Inventory, you'll need to make sure that Inventory is
[configured]({% link _docs/latest/configure/inventory/index.md %}) and the
proper [GCP]({% link _docs/latest/concepts/service-accounts.md %}) and
[GSuite]({% link _docs/latest/configure/gsuite.md %}) permissions are setup
for your Forseti GCP service account.

To display Inventory flag options, run `forseti inventory -h`.

### Create a new inventory

```bash
$ forseti inventory create
```

The command above will start a new inventory process, you can track the status by using the `list` command.

### Create a new inventory along with a data model

Because the data model is widely used in Forseti, it can be helpful to create
the data model along with the newest Inventory.

```bash
$ forseti inventory create --import_as <MODEL_NAME>
```

### List all the existing inventories

```bash
$ forseti inventory list
```

The command above will list all the existing inventories along with their statuses.

### Get an inventory

```bash
$ forseti inventory get <INVENTORY_INDEX_ID>
```

The command above will get the summary of the inventory with inventory_index_id = `<INVENTORY_INDEX_ID>`. 
`<INVENTORY_INDEX_ID>` can be retrieved by the `list` command.

### Delete an inventory

```bash
$ forseti inventory delete <INVENTORY_INDEX_ID>
```

The command above will delete the inventory with inventory_index_id = `<INVENTORY_INDEX_ID>`. 

### Purge inventories

```bash
$ forseti inventory purge <RETENTION_DAY>
```

The command above will delete all the inventories that are older than `<RETENTION_DAY>`.
Note: `<RETENTION_DAY>` is number of days to retain the data. If not specified, then the 
value in forseti config yaml file will be used.


## What's next
- Learn about [configuring Inventory]({% link _docs/latest/configure/inventory/index.md %}).
