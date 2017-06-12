---
permalink: /modules/optional/explain/
---
# IAM Explain

IAM Explain is a Client-Server based application to designed to help
administrators, auditors and users of Google Cloud to understand, test
and develop their Cloud IAM policies.

IAM Explain is deployed on a separate virtual machine and uses the
Forseti inventory to build a model of the Cloud IAM policies to offer
its service. In the current version, a command-line interface is provided.

Note: IAM Explain is still early and its API under heavy development.
Until a first stable API version is released, third party clients are not
supported.

## Running the Server

The IAM Explain Server connects to the Forseti database while maintaining its
database for the IAM models and simulations. Its only permissions required are
to query the databases, hence it requires at least the 'Cloud SQL Client' role.

* The standard way to run the server on a deployment is using its systemd scripts

  ```sh
  $ systemctl start cloudsqlproxy
  $ systemctl start forseti
  ```

* For local installations, the server can be directly started

  ```sh
  $ forseti_api '[::]:50051' 'mysql://root@127.0.0.1:3306/forseti_db'\
     'mysql://root@127.0.0.1:3306/explain_db' playground explain
  ```

* If you want IAM Explain to connect to a Cloud SQL instance, use the sql proxy

  ```sh
  $ cloud_sql_proxy -instances=$PROJECT:$REGION:$INSTANCE=tcp:3306
  ```

## Running the Client

The IAM Explain Client implements a hierarchical command parsing strategy.
At the top level, commands divide into 'explain' and 'playground'.

* Importing a model from Forseti
  ```sh
  $ forseti_iam explain create_model forseti
  ```

* Creating an empty model
  ```sh
  $ forseti_iam explain create_model empty
  ```

* Using a model

  ```sh
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

## Using the simulator

Playground or simulator allows the inspection and modification of the current
state of the model. It is already a powerful tool by itself since it allows
setting new policies and checking on them. However, in combination with the
explainer it allows asking 'what if' questions by modifying the state using
simulator and comparing the output of explainer.

## Using the explainer

Explainer was built to enumerate and reason about Cloud IAM policies. It can
enumerate access by resource or member, answer why a principal has access to
a certain resource or possible strategies on how to grant a specific access.
If this is still not enough for you use case, you might want to use the
denormalizer which calculates all the (Principal, Permission, Resource)
triples which hold for the model. This even allows a primitive 'diffing'
between the access of two entire models, e.g. comparing the access at two
different points in time.

