---
title: IAM Explain
order: 202
---
# {{ page.title }}

This quickstart describes how to set up IAM Explain for Forseti Security.
IAM Explain is a client-server based application that helps administrators,
auditors, and users of Google Cloud to understand, test, and develop Cloud
Identity and Access Management (Cloud IAM) policies. It can enumerate access by
resource or member, answer why a principal has access to a certain resource, or
offer possible strategies for how to grant a specific resource. You'll use a
command-line interface to deploy IAM Explain on a separate virtual machine and
use Forseti Inventory to build a model of Cloud IAM policies to offer its
service.

For more detail about your Cloud IAM policies, you can use the denormalizer,
which calculates all the principals, permissions, and resources for the model.
It also allows a primitive "diff" of the access between two full models, such
as comparing the access at two different points in time. To use the
denormalizer, run `forseti_iam explainer denormalize` or
`forseti_iam explainer --help`. You can also explore the `forseti_iam` tool by
using `forseti_iam --help`.

Because IAM Explain and its API are still in early development, third party
clients won't be supported until a first stable API version is released.

## Before you begin

Before you set up and deploy IAM Explain, you'll need the following:

  - A running Forseti instance with [group collection enabled]({% link _docs/howto/gsuite-group-collection.md %})
  - A service account with the Cloud SQL Client role. For security purposes,
  it's best to create a separate service account for IAM Explain. However, you
  can use your [Forseti Security service account]({% link _docs/howto/local-deployment.md %}#creating-service-accounts)
  if you want.
  - An SQL instance. You can use the SQL instance you created when you
  set up Forseti Security, or create a new, separate SQL instance for IAM
  Explain. Learn how to [create a Cloud SQL instance](https://cloud.google.com/sql/docs/mysql/quickstart).
  - A new database for IAM Explain inside the SQL instance.

## Customizing the deployment template

You can use the provided
[sample IAM Explain deployment](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/samples/deployment-manager/deploy-explain.yaml.sample)
to customize your deployment. You'll need to point to the SQL instance you want
to use for IAM Explain. To prepare your IAM Explain template, update the
following values:

  - `EXPLAIN_DATABASE_INSTANCE_NAME`: the Cloud SQL instance that hosts the
  IAM Explain database, in the form of `{project}:{region}:{instance-name}`.
    - This may be the same value as `FORSETI_DATABASE_INSTANCE_NAME`.
  - `FORSETI_DATABASE_INSTANCE_NAME`: the Cloud SQL instance that hosts the
  Forseti database, in the form of `{project}:{region}:{instance-name}`.
    - This may be the same value as `EXPLAIN_DATABASE_INSTANCE_NAME`.
  - `YOUR_SERVICE_ACCOUNT`: the service account you created for IAM Explain,
  or the shared Forseti service account.
  - `src-path, release-version`: the path and release version of IAM Explain
  you want to use.
    - It's best to use an IAM Explain release version that's equal to or higher
    than the Forseti release you're using.
    - IAM Explain supports the same version identifiers as Forseti, starting
    with `1.0.3`.

After you configure the deployment template variables, run the following
command to create a new deployment:

````
gcloud deployment-manager deployments create iam-explain \
--config path/to/deploy-explain.yaml
````

## Running the server

The IAM Explain server uses its own database for IAM models and simulations,
but queries the Forseti database for new imports. To run the IAM Explain server
together with a Forseti deployment, use one of the following methods:

  - Standard start/restart, if you used the deployment manager to create IAM
  Explain:

        systemctl start cloudsqlproxy
        systemctl start forseti

    - The services should automatically start right after the deployment.
    - You can find a deployment log at `/tmp/deployment.log`.

  - Start the server in a local installation:

        forseti_api '[::]:50051' 'mysql://root@127.0.0.1:3306/forseti_db'\
        'mysql://root@127.0.0.1:3306/explain_db' playground explain

    - Use the SQL proxy to establish a connection to the Cloud SQL instance:

          cloud_sql_proxy -instances=$PROJECT:$REGION:$INSTANCE=tcp:3306


## Running the client

The IAM Explain client uses hierarchical command parsing. At the top level,
commands divide into "explain" and "playground".

### Setting up an explain model

To run the client, you'll first set up a model using one of the following
methods:


  - Importing a Forseti model:

        forseti_iam explain create_model forseti

  - Creating an empty model:

        forseti_iam explain create_model empty

### Using an explain model

To use a model, run the commands below:

````
forseti_iam --out-format json explainer list_models
  {
    "handles": [
      "2654f082f572a9c328cd5bb6f7011b08",
      "33ff45caa913837eb7680056c05d5f31",
  }
forseti_iam --use_model 2654f082f572a9c328cd5bb6f7011b08 \
  playground list_resources
  ...
forseti_iam --use_model 2654f082f572a9c328cd5bb6f7011b08 \
  explainer denormalize
  ...
````

### Using the playground

IAM Explain playground is a simluator that allows you to inspect and modify
the current state of a model. For example,
`forseti_iam playground list_resources` displays all the resources available
in the model. On its own, it enables you to set and check new policies. When
used with an explain model, it also enables you to simulate a state
modification and compare it to the live explain output. To view all the
commands available for IAM Explain playground, run
`forseti_iam playground --help`.
