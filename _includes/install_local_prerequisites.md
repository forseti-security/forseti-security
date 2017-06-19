### Setup Cloud SQL
Forseti uses Cloud SQL to store data. It connects to the Cloud SQL instance with the Cloud SQL proxy, which authenticates to GCP with your Google credentials.

  1. Create a new instance in the [SQL page of GCP console](https://console.cloud.google.com/sql).
     * Select second generation for the instance type.
     * Specify Instance ID.
     * Select MySQL 5.7 version.
     * Select db-n1-standard-1 machine type.
     * Change storage capacity to 25GB.
     * Fill in other details, as desired.
     * Enter or generate a password for the root user.
     * Click Create button.
  1. Configure Instance Access Control
     * Create a new user (e.g. `forseti_user`) with [read/write privileges](https://cloud.google.com/sql/docs/mysql/users?hl=en_US#privileges).
     * Do not set password for the new user, as Cloud SQL Proxy will handle the
     authentication to your instance.
  1. Create New Database
     * Enter a name (e.g. `forseti_security`).
  1. We recommend using the
     [SQL Proxy](https://cloud.google.com/sql/docs/mysql-connect-proxy#connecting_mysql_client)
     to proxy your connection to your Cloud SQL instance.

     The `cloud_sql_instance_name` below can be found in the Cloud SQL dashboard
     in the instance details page, then looking for "instance connection name"
     under the Properties section.

     ```sh
     # in separate terminal
     $ <path_to_cloud_sql_proxy>/cloud_sql_proxy -instances=<cloud_sql_instance_name>=tcp:3306
     ```

### Install `mysql_config`
The MySql-python library requires `mysql_config` to be present in your system.

```sh
# Ubuntu
# Note: If libmysqlclient-dev doesn't install `mysql_config`, then try also installing `mysql_server`.
$ sudo apt-get install libmysqlclient-dev

# OSX
$ brew install mysql
```

### Install virtualenv
```sh
$ sudo apt-get install python-pip
$ sudo pip install --upgrade virtualenvwrapper
```
