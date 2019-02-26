---
title: Model
order: 102
---

# {{ page.title }}

Forseti models are built on top of the raw Inventory data to help show how the
data is related.

To learn more about the Forseti model, see [Models]({% link _docs/v2.10/concepts/models.md %}).

---

## Running Forseti model

### Creating a data model

To create a data model from a specific inventory, run the following command:

```bash
forseti model create --inventory_index_id <INVENTORY_INDEX_ID> <MODEL_NAME>
```

When you create the data model, you might get a `PARTIAL_SUCCESS` status if you get
expected warnings. For example, an alpha version role doesn't contain any
permissions, which is logged as a warning in the data model. A model with status of
`PARTIAL_SUCCESS` is safe to use.

To display all the errors and warnings of the data model, use the `get` command.

### Using a data model

To set the data model for your current session, run the following command:

```bash
forseti model use <MODEL_NAME>
```

### Listing all the existing data models

To list all existing data models and their statuses, run the following command:

```bash
forseti model list
```

### Getting a data model

To get the summary of an inventory with a specific model name, run the following command:

```bash
forseti model get <MODEL_NAME>
```

### Deleting a data model

To delete a specific data model, run the following command:

```bash
forseti model delete <MODEL_NAME>
```

## What's next

* Learn how to query the data model using [Explain]({% link _docs/v2.10/use/cli/explain.md %}).
