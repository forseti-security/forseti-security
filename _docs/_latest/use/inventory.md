---
title: Inventory
order: 002
---

# {{ page.title }}

Forseti Inventory collects and stores information about your Google Cloud Platform (GCP)
resources. Forseti Scanner and Enforcer use Inventory data to perform operations.

## Running Inventory

Before you start using Inventory, you'll need to make sure you have the  
[proper permission setup]({% link _docs/latest/configure/gsuite-group-collection.md %}) 
for your Forseti gcp service account.

To display Inventory flag options, run `forseti inventory -h`.

### Create a new inventory

```bash
$ forseti inventory create
```

The command above will start a new inventory process, you can track the status by using the `list` command.

### Create a new inventory along with a data model

Since the data model is widely used in Forseti so sometimes it's handy 
to just create the dada model along with the newest inventory.

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
