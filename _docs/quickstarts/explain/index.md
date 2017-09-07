---
title: IAM Explain
order: 202
---
# {{ page.title }}

This quickstart describes how to set up IAM Explain using the automatic script.
If you are interested in a manually deployment or want to gain an understanding of how IAM Explain's deployment works internally, please refer to the [Howto document]({% link _docs/howto/explain/manual-deploy.md %}#enable-domain-wide-delegation-in-g-suite) for details.

IAM Explain is a client-server based application that helps administrators,
auditors, and users of Google Cloud to understand, test, develop and debug Cloud
Identity and Access Management (Cloud IAM) policies. It can enumerate access by
resource, member, role or permission and answer why a principal has access on a
certain resource, or offer possible strategies for how to grant access.
In the latest version, IAM Explain is functional complete without a Forseti
deployment (see below for steps).
When you deploy IAM Explain, it creates a GCE instance and a MySQL database.
In order to use IAM Explain, you can login to the GCE instance and use the command line
tool `forseti_iam`. See below for usage examples.

Because IAM Explain and its API are still in early development, third party
clients won't be supported until a first stable API version is released. Only command
line is currently supported but feel free to experiment with the API as well.

## Before you begin

Before you set up and deploy IAM Explain, you need to perform the following steps:

  - Create a new project in your organization so IAM Explain's data will be protected from other users in the organization. Note that individuals with access on an organization or folder level might still have access though.
  - Enable the billing of the created project.
  - Activate Google Cloud Shell, clone the master branch of [Forseti repo](https://github.com/GoogleCloudPlatform/forseti-security).

  ```bash
  $ git clone -b master https://github.com/GoogleCloudPlatform/forseti-security.git
  ```

## Automatic deployment

You can run the bash script for automatic IAM Explain deployment and follow its instructions.

  ```bash
  $ bash forseti-security/scripts/iam_auto_deployment.sh
  ```

After the automatic deployment script ends, please follow the [instruction to enable group collection]({% link _docs/howto/explain/explain-gsuite-setup.md %}#enable-domain-wide-delegation-in-g-suite) on the GSuite crawling service account to complete the deployment.

## Using IAM Explain

You should now be able to login to your IAM Explain instance and use the `forseti_iam` command. 

## Running the client

The IAM Explain client uses hierarchical command parsing. At the top level,
commands divide into "explainer" and "playground".

### Getting started

The first thing you need to do with a fresh instance is to create an inventory:

```bash
$ forseti_iam inventory create
```

This will crawl the organization and create an inventory in a single table for long term storage.

In order to the other services like playground and explain, you need to create a so called model. A model is a data model instance created from an inventory. You can have multiple models at the same time from the same or different inventories. Models are what you work on, inventory is just the long term storage format. In order to create a model, the first question is which inventory you want to create it from. Use the inventory list to see what inventories are available or create a new one using the above command.

```bash
$ forseti_iam inventory list
```

In order to create a model from an inventory, use the inventory id. You can choose an arbitrary name to associate your work with the model:
```bash
$ forseti_iam explainer create_model --id ID inventory NAME
```

In order to use a newly created or existing model, use the list functionality and either set the handle of the model in the command line or using an environment variable:

```bash
$ forseti_iam explainer list_models
$ export IAM_MODEL=....
$ forseti_iam explainer list_permissions
```

Or:

```bash
$ forseti_iam explainer list_models
$ forseti_iam --use_model ... explainer list_permissions
```

From here, we recommend you extensively use the `--help` parameter in all variations to explore the functionality of each service. Playground is the simulator which allows you to change a model, Explainer is the tool that allows you to ask questions stated in the introduction like 'who has access to what and why'.
