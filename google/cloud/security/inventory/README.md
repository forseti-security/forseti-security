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
4. Follow these instructions to establish a secure connection using [SQL Proxy](https://cloud.google.com/sql/docs/mysql-connect-proxy#connecting_mysql_client)


## How to Run
After running setup.py, as long as your virtualenv is activated, then you can be in any directory to invoke the console script:

```sh
$ forseti_inventory
```

You can also use the convenience [dev_inventory.sh script](/scripts) to run forseti_inventory. Make a copy of dev_inventory.sh.sample as dev_inventory.sh, edit the script for the appropriate commandline flags, and invoke the script from the repo root to run inventory.

```sh
$ cd path/to/forseti-security
$ scripts/dev_inventory.sh
```

## How to Test
Look at the test instruction in this [README](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/README.md#tests).

## How to Add New Resource to Inventory

In general, it's straightforward to add new resource to inventory.
The workflow is designed to be generic, with the main steps as:
* define the database table schema to store the resource data
* create a new pipeline worker, to process the new table and the table fieldnames
* write a transformation to flatten the data returned by GCP APIs into a format
that's ingestable by the database table

Look at this PR for an [end-to-end example loading of a resource](https://github.com/GoogleCloudPlatform/forseti-security/pull/26).

Step-by-Step:
1. Design the applicable database table schema.  This schema will reflect
how data from GCP APIs will be flattened and stored in a database table.
Besides the relational data, we also aim to store the raw API data as json
to assist troubleshooting.  Create a PR for this to be reviewed first
before rest of the code is written.  This will save a lot of work.

2. Once the database PR is merged, create a loader pipeline for your resource.
This loader pipeline will then be installed in the runner inventory_loader.py.

3. Get the data from GCP.  [See if the API to get your data already exists.](https://github.com/GoogleCloudPlatform/forseti-security/tree/master/google/cloud/security/common/gcp_api)
If not, it's your chance to contribute a new one.

4. Data from GCP api is not normalized and can not be fitted into the
database table.  You will have to write a function to transform the data.
Please write a [test for this transform function](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/tests/inventory/transform_util_test.py).

5. Load the flattened data into database table, with the load_data() in [dao.py](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/common/data_access/dao.py).
    * add the new table to CREATE_TABLE_MAP
    * use the [csv_writer](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/common/data_access/csv_writer.py) to write the API data to csv
    * create a new map of the fieldnames that matches the CSV column to the database columns
    * add the new map to CSV_FIELDNAME_MAP
    * call the load_sql_provider to generate the sql to load the data for your resource
    * execute the load_data sql command

## Tips & Tricks
* It is helpful to use a MySql GUI tool to inspect the table data.
