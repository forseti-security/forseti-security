---
title: Model
order: 004
---

# {{ page.title }}

Forseti models are built on top of the raw Inventory data to help show how the
data is related.

To learn more about the Forseti model, see [Models]({% link _docs/latest/concepts/models.md %}).

---

## Running Forseti model

### Creating a data model

```bash
$ forseti model create --inventory_index_id <INVENTORY_INDEX_ID> <MODEL_NAME>
```

The command above will create a data model `<MODEL_NAME>` from inventory `<INVENTORY_INDEX_ID>`.

Note: It is likely you will be getting `PARTIAL_SUCCESS` status when you
create the data model because you might be getting expected warnings.
For example, roles in their alpha version will not contain any permissions
and we will log that as a warning in the data model.  So, model with status of
`PARTIAL_SUCCESS` is safe to use.

To display all the errors and warnings of the data model, use the `get` command.

### Using a data model

```bash
$ forseti model use <MODEL_NAME>
```

The command above will set the data model of the current session to `<MODEL_NAME>`.

### Listing all the existing data models

```bash
$ forseti model list
```

The command above will list all the existing data models along with their statuses.

### Getting a data model

```bash
$ forseti model get <MODEL_NAME>
```

The command above will get the summary of the inventory with model name = `<MODEL_NAME>`.


### Deleting a data model

```bash
$ forseti model delete <MODEL_NAME>
```

The command above will delete the data model with model name = `<MODEL_NAME>`.

## What's next

Learn how to query the data model using [Explain]({% link _docs/latest/use/explain.md %}).