---
title: Explain
order: 000
---
# {{ page.title }}

This guide describes how to configure Explain for Forseti Security.

Explain helps you understand the Cloud Identity and Access Management
(Cloud IAM) policies that affect your Google Cloud Platform (GCP) resources.
It can enumerate access by resource or member, answer why a principal has access 
to a certain resource, or offer possible strategies for how to grant a specific 
resource.

## Running Explain

Before you start using Explain, you'll first select the data model you
want to use.

To review the hierarchy of commands and explore Explain functionality, use
`–help`.

### Creating a data model

Data model is built using the inventory data we created through the Forseti Inventory service.

Instructions on how to run Forseti Inventory can be found [here]({% link _docs/latest/use/inventory.md %}).

Once you have the inventory ready, retrieve the inventory_index_id and use it to create the data model as follows:

```bash
$ forseti model create --inventory_index_id <INVENTORY_INDEX_ID> <MODEL_NAME>
```

### Listing all the data model

```bash
$ forseti model list
```

### Selecting a data model

```bash
$ forseti model use <MODEL_NAME>
```

### Querying the data model through Explain

Following are some example commands you can run to query the data model.

##### Listing all resources in the data model

```bash
$ forseti explainer list_resources
```

##### Filter the results and list resources only in a folder

```bash
$ forseti-client-XXXX-vm> forseti explainer list_resources --prefix organization/1234567890/folder/folder-name
```

For more advanced Explain commands, please refer to the guide [here]({% link _docs/latest/use/cli.md %}).

## What's next

- Read more about [the concepts of data model]({% link _docs/latest/concepts/models.md %}).
- Learn about the [complete list of functionalities]({% link _docs/latest/use/cli.md %}) available in Explain.
