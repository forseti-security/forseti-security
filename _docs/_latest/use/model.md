---
title: Model
order: 004
---

# {{ page.title }}

Forseti models built on top of the raw inventory data to provide us with a better 
understanding of how the data is related to each other.

You can learn more about the concept of Forseti model [here]({% link _docs/latest/concepts/models.md %}).

## Running Forseti model

### Creating a data model

```bash
$ forseti model create --inventory_index_id <INVENTORY_INDEX_ID> <MODEL_NAME>
```

The command above will create a data model `<MODEL_NAME>` from inventory `<INVENTORY_INDEX_ID>`.

Note: The status of the Data model can be `SUCCESS`, `PARTIAL_SUCCESS` and `BROKEN`, most likely
you will be getting `PARTIAL_SUCCESS` for your data model because there are expected warnings that you
might be getting. For example, roles in their alpha version will not contain any permissions and we
will log that as a warning in the data model. You can see all the errors/warnings of the data model
with the `get` command. Model with status = `PARTIAL_SUCCESS` is completely safe to use.

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

Once we have the data model ready, you can learn how to query the data model using Forseti Explainer
[here]({% link _docs/latest/use/explain.md %}).