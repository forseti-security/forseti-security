---
title: Explain
order: 000
---
# {{ page.title }}

This guide describes how to set up Explain for Forseti Security.
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

### Selecting a data model

```bash
$ forseti model use <YOUR_MODEL_NAME>
```

### Accessing a data model

Following are some example commands to list and filter a data model.

#### Listing all resources in the data model

```bash
$ forseti explainer list_resources
```

#### Filter the results and list resources only in a folder

```bash
$ forseti-client-XXXX-vm> forseti explainer list_resources --prefix organization/1234567890/folder/folder-name
```

#### List all members in the data model

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members
```

#### Filter the results and list members with a prefix match

```bash
$ forseti-client-XXXX-vm> forseti explainer list_members --prefix test
```

## What's next

- Read more about [the concepts of data model]({% link _docs/concepts/models.md %}).
- Learn about the [complete list of functionalities]({% link _docs/use/cli.md %}) available in Explain.
