---
title: Inventory
order: 002
---
# Forseti Inventory Quickstart

This quickstart describes how to get started with Forseti Inventory. Forseti
Inventory collects and stores information about your Google Cloud Platform
(GCP) resources. Forseti Security scans and Enforcer use Inventory data to
perform operations.

## Resource Coverage

These are the resources that have coverage in Forseti, or planned to have 
coverage.  If you don't see something that you are interested in, please open
an issue or contribute!

| Resource                        | Inventory     | Scanner       | Enforcer      |
| ------------------------------- | ------------- | ------------- | ------------- |
| Organizations                   | Done          | N/A           | Open          |
| Org IAM Policies                | Done          | Done          | Open          |
| Projects                        | Done          | N/A           | Open          |
| Project IAM Policies            | Done          | Done          | Open          |
| Groups                          | Done          | Done          | Open          |
| GroupMembers                    | Done          | Done          | Open          |
| Folders                         | Done          | In Progress   | Open          |
| Firewall Rules                  | Done          | Open          | Done          |
| Networks                        | Open          | Open          | Open          |
| Subnetworks                     | Open          | Open          | Open          |
| Load Balancer Forwarding Rules  | Done          | In Progress   | Open          |
| Buckets                         | Done          | Done          | Open          |
| BucketACL                       | Done          | Done          | Open          |
| Cloud SQL Inventory             | Done          | Done          | Open          |
| BigQuery                        | Done          | In Progress   | Open          |
| Dasher Users                    | Open          | Open          | Open          |
| GrantableRoles                  | In Progress   | Open          | Open          |
| GAE                             | In Progress   | Open          | Open          |
| GCE Instances                   | Done          | In Progress   | Open          |
| GCE Instance Groups             | Done          | In Progress   | Open          |
| GCE Instance Group Managers     | Done          | In Progress   | Open          |
| GCE Instance Templates          | Done          | In Progress   | Open          |
| GCE Backend Services            | Done          | In Progress   | Open          |

## Executing the inventory loader

After you install Forseti, you can use the `forseti_inventory` command to
access the Inventory tool. If you installed Forseti in a virtualenv, activate
the virtualenv first.


To display Inventory flag options, run the following commands:
````
sh
forseti_inventory --helpshort
````

## Configuring Inventory pipelines to run
To run Forseti Inventory, you'll need a configuration file. Download
the [inventory_conf.yaml sample file](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/samples/inventory/inventory_conf.yaml)
, then run the command below to provide the configuration file to
`forseti_inventory`:

````
sh
forseti_inventory --config_path PATH_TO/inventory_conf.yaml
````

Forseti Inventory is now set up to run for your specified projects.
