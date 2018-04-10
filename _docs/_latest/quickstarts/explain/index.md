---
title: Explain
order: 000
---
# {{ page.title }}

This quickstart guide describes how to set up IAM Explain for Forseti Security.
IAM Explain helps administrators, auditors, and users of Google Cloud to understand, 
test, and develop Cloud Identity and Access Management (Cloud IAM) policies. 
It can enumerate access by resource or member, answer why a principal has access 
to a certain resource, or offer possible strategies for how to grant a specific 
resource.

## Running IAM Explain

Forseti Explain runs on a data model, so before you start using Explain, 
you'll first select a model to use.

You can use ‘–help’ to go through the hierarchy of commands and explore the 
functionality. Only the basic examples are shown here.

##### Selecting a data model

```bash
$ forseti model use <YOUR_MODEL_NAME>
```

##### Listing all resources in the data model

```bash
$ forseti explainer list_resources
```

##### Filter the results and list resources only in a folder

```bash
$ forseti-client-XXXX-vm> forseti explainer list_resources --prefix organization/1234567890/folder/folder-name
```

##### List all members in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members
```

##### Filter the results and list members with a prefix match

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members --prefix test
```

## What's next

- Read more about [the concepts of data model]({% link _docs/concepts/models.md %}).
- Learn about the [complete list of functionalities]({% link _docs/use/cli.md %}) available in Forseti explainer.