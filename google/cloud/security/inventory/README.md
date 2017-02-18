# Inventory
This is the Inventory component of Forseti Security tool.

## Pre-requisites
If you haven't already, install the Forseti packages by using the setup.py in the top-level directory of this repo. This will install the required Python libraries and setup the tool environment. More instructions are in the top-level README.

## How to Configure

### Enable APIs in Google Cloud Platform
1. Google Cloud Resource Manager
2. Google Cloud SQL
3. Google Cloud SQL API

### Create Cloud SQL Instance
1. Create a new instance in the [SQL page of GCP console](https://console.cloud.google.com/sql).
    * Select second generation.
    * Specify Instance ID.
    * Select MySQL 5.7 version.
    * Select db-n1-standard-1 machine type.
    * Select 25GB storage capacity.
    * Select High Availability (HA) mode.  If you skip the failover replica id, a default one will be provided.
    * Fill in other details, as desired.
    * Click Create button.
2. Configure Users Access Control
    * Change password for root user.
    * Create a new user with [read/write privileges](https://cloud.google.com/sql/docs/mysql/users?hl=en_US#privileges).
3. Create New Database
    * Enter a name.
4. Follow this instruction to establish a secure connection using [SQL Proxy](https://cloud.google.com/sql/docs/mysql-connect-proxy#connecting_mysql_client)

### Configure Data Access configs.yaml file.
1. In the repo root's config/ directory, make a copy of db.yaml.sample.
2. Rename the copy to "db.yaml" and keep in the config/ directory.
3. Fill in the indicated parameters for the Cloud SQL instance.
4. Save a copy (e.g. Google Cloud Storage).

### Configure Inventory configs.yaml file.
1. In the repo root's config/ directory, make a copy of inventory.yaml.sample.
2. Rename the copy to "inventory.yaml" and keep in the config/ directory.
3. Fill in the indicated parameters in the configurations file.
4. Save a copy (e.g. Google Cloud Storage).


## How to Run
After running setup.py, as long as your virtualenv is activated, then you can be in any directory to invoke the console script:

```sh
$ forseti_inventory
```

## How to Test
Look at top-level [README](/README.md).

## Tips & Tricks
* It is helpful to use a mysql GUI tool to inspect the table data.
