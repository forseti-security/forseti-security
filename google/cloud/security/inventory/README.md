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
If you are running in the local environment, you need to install and configure
service account key.

### Install Service Account Key
1. Create a key for your project's Compute Engine default service account
in the [GCP console](https://console.cloud.google.com/iam-admin/serviceaccounts).
2. Permission the service account with the following IAM policy:
    * Project Browser
    * Cloud SQL Editor 
3. Download the key to your local env.
4. Configure the [Application Default Credentials](https://developers.google.com/identity/protocols/application-default-credentials)
to env variable to reference this key.
```sh
$ export GOOGLE_APPLICATION_CREDENTIALS="<path to your service account key>"
```

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

## Tips & Tricks
* It is helpful to use a mysql GUI tool to inspect the table data.
