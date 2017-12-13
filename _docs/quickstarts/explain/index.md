---
title: IAM Explain
order: 202
---
# {{ page.title }}

IAM Explain is not part of the main Forseti releases from master. Please
deploy from the [IAM Explain experimental branch](https://github.com/GoogleCloudPlatform/forseti-security/tree/explain-experimental).

This quickstart describes how to set up IAM Explain for Forseti Security.
IAM Explain is a client-server based application that helps administrators,
auditors, and users of Google Cloud to understand, test, and develop Cloud
Identity and Access Management (Cloud IAM) policies. It can enumerate access by
resource or member, answer why a principal has access to a certain resource, or
offer possible strategies for how to grant a specific resource. You'll use a
command-line interface to deploy IAM Explain on a dedicated virtual machine.

For more detail about your Cloud IAM policies, you can use the denormalizer,
which calculates all the principals, permissions, and resources for the model.
It also allows a primitive "diff" of the access between two full models, such
as comparing the access at two different points in time. To use the
denormalizer, run `forseti_iam explainer denormalize` or
`forseti_iam explainer --help`. You can also explore the `forseti_iam` tool by
using `forseti_iam --help`.

Because IAM Explain and its API are still in early development, third party
clients won't be supported until a first stable API version is released.

## Deploying IAM Explain 

You can use the provided [IAM Explain deployment script](https://github.com/GoogleCloudPlatform/forseti-security/blob/explain-experimental/scripts/iam_auto_deployment.sh) that will walk you through
the deployment. Make sure you have the permission inside your organization to
create projects, set IAM policies, create service accounts and enable the required
APIs.

You can directly clone the experimental branch into your cloud shell and execute
the deployment script:

  ```bash
  $ git clone -b explain-experimental \
    https://github.com/GoogleCloudPlatform/forseti-security.git
  $ bash forseti-security/scripts/iam_auto_deployment.sh
  ```


## First start

After the deployment script is finished, allow a few minutes for the virtual machine
startup script to install all dependencies and start the services. You can observe
the progress by looking at the deployment log at /tmp/deployment.log.
## Running the client

The IAM Explain client uses hierarchical command parsing. At the top level,
commands divide into "explainer" and "playground".

### Setting up an explain model

You can use '--help' to go through the hierarchy of commands and explore
the functionality. Only the basic examples are shown here.

To run the client, you'll first create an inventory. This process can take
some time depending on the number of resources in your environment.

```bash
$ forseti_iam inventory create
$ forseti_iam inventory list
```

After the creation of an inventory, create a queryable data model. You need
to refer to the inventory id as it shows up under the previous list command

```bash
$ forseti_iam explainer create_model --id 1 inventory
```

Once you have a queryable data model, you can switch into it by getting the
handle of the model and setting an environment variable (IAM_MODEL) or directly
specifying it in the command line using '--use-model'

```bash
$ forseti_iam --use-model ... explainer denormalize
```

## Running the server

The IAM Explain server uses its own database for IAM models, simulations and inventory.


  - Standard start/restart, if you used the deployment manager to create IAM
  Explain:

      ```bash
      $ systemctl start cloudsqlproxy
      $ systemctl start forseti
      ```

    - The services should automatically start right after the deployment.
    - You can find a deployment log at `/tmp/deployment.log`.

### Using IAM Explain

To use a model, run the commands below:

  ```bash
  $ forseti_iam --out-format json explainer list_models

    {
      "handles": [
        "2654f082f572a9c328cd5bb6f7011b08",
        "33ff45caa913837eb7680056c05d5f31",
    }
    
  $ forseti_iam --use_model 2654f082f572a9c328cd5bb6f7011b08 \
    playground list_resources
    
    ...
    
  $ forseti_iam --use_model 2654f082f572a9c328cd5bb6f7011b08 \
    explainer denormalize
    
    ...
  ```

### Using the playground

IAM Explain playground is a simluator that allows you to inspect and modify
the current state of a model. For example,
`forseti_iam playground list_resources` displays all the resources available
in the model. On its own, it enables you to set and check new policies. When
used with an explain model, it also enables you to simulate a state
modification and compare it to the live explain output.

To view all the
commands available for IAM Explain playground, run
`forseti_iam playground --help`.
