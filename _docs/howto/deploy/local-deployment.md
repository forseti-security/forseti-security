---
title: Local Deployment
order: 103
---
#  {{ page.title }}

This page explains how to use the gcloud command-line tool to set up Forseti for
your Google Cloud Platform (GCP) resources.

## Before you begin

To complete this quickstart, you will need:

- A GCP organization.
- A GCP project (in above organization) for Forseti Security with billing enabled.
- The ability to assign roles on the Organization IAM policy of your organization.

## Setting up Forseti Security

{% include docs/howto/deployment_prerequisites.md %}

### Setting up Cloud SQL

Forseti stores data in Cloud SQL. You can connect to the Cloud SQL instance by
using the Cloud SQL proxy to authenticate to GCP with your Google credentials, 
instead of opening up network access to your Cloud SQL instance.
To set up your Cloud SQL instance for Forseti, follow the steps below:

1.  Go to the [Cloud Console SQL page](https://console.cloud.google.com/sql) and
    follow the steps below to create a new instance:
    1.  Select a **MySQL** database engine.
    1.  Select a **Second Generation** instance type.
    1.  On the **Create a MySQL Second Generation instance** page, enter an
        **Instance ID** and **Root password**, then select the following
        settings:
        1.  **Database version:** MySQL 5.7
        1.  **Machine type:** db-n1-standard-1 machine type
        1.  **Storage capacity:** 25 GB
    1.  Add or modify other database details as you wish.
    1.  When you're finished setting up the database, click **Create**.
1.  [Create a new user](https://cloud.google.com/sql/docs/mysql/create-manage-users#creating),
    e.g. `forseti_user`,
    with [read/write privileges](https://cloud.google.com/sql/docs/mysql/users?hl=en_US#privileges)
    for Forseti to access the database. Don't set a password for the new user.
    This will allow Cloud SQL Proxy to handle authentication to your instance.
1.  [Create a new database](https://cloud.google.com/sql/docs/mysql/create-manage-databases#creating_a_database),
    e.g. `forseti_security`.
1.  Use the [SQL Proxy](https://cloud.google.com/sql/docs/mysql-connect-proxy#connecting_mysql_client)
    to proxy your connection to your Cloud SQL instance. Your
    INSTANCE_CONNECTION_NAME is the **Instance Connection Name** under
    **Properties** on the Cloud SQL dashboard instance details, with the format "PROJECTID:REGION:INSTANCEID".
    
      ```bash
      $ <path/to/cloud_sql_proxy> -instances=INSTANCE_CONNECTION_NAME=tcp:3306
      ```
      
1. Make a note of your the Cloud SQL user you created (e.g. "forseti_user") as well as 
   the database name (e.g. "forseti_security" -- this is NOT the ID of your Cloud SQL instance). 
   You will need these for your forseti_conf.yaml later.

### Installing mysql_config

The MySql-python library requires the `mysql_config` utility to be present in your system.
Following are example commands to install `mysql_config`:

  ```bash
  # Ubuntu
  # Note: If libmysqlclient-dev doesn't install `mysql_config`, then try also installing `mysql_server`.
  $ sudo apt-get install libmysqlclient-dev

  # OSX, using homebrew
  $ brew install mysql
  ```

### Creating a virtualenv

Use the commands (or whatever the equivalent is for your Linux/OS X system) 
below to install and create a virtualenv:

  ```bash
  # install virtualenvwrapper
  $ sudo apt-get install python-pip
  $ sudo pip install --upgrade virtualenvwrapper

  # create a virtualenv
  $ mkvirtualenv forseti-security
  $ workon forseti-security
  ```

### Getting the source code

Use the command below to clone the repo if you haven't already:

  ```bash
  $ git clone https://github.com/GoogleCloudPlatform/forseti-security.git
  ```

### Installing build dependencies

To install required build dependencies, run the following commands:

  ```bash
  $ pip install grpcio grpcio-tools google-apputils
  ```

### Building proto files and running the python setup

To build proto files and run the python setup, navigate to your cloned repo and
use the following command:

  ```bash
  $ python build_protos.py --clean
  $ python setup.py install
  ```

### Executing Forseti commands

After you complete the above steps, you should be able to run the following
command-line tools:

-   `forseti_inventory`
-   `forseti_scanner`
-   `forseti_enforcer`
-   `forseti_api`
-   `forseti_iam`

To display the flag options for each tool, use the `--helpshort` or `--helpfull`
flags.
