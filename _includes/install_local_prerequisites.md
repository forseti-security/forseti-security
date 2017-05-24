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

### Install the `protoc` compiler
Download the [protoc pre-built binary](https://github.com/google/protobuf/releases).
Forseti Security has been tested with the protoc 3.0+
(the zip file is named something like `protoc-VERSION-OS-ARCH.zip`).
It's recommended to use an updated version of protoc
(e.g. 3.2.0 fixed a lot of bugs).

Unzip the file and copy the `protoc` binary from the extracted`bin/` directory
to somewhere like /usr/local/bin (or somewhere similar on your path). If `which
protoc` doesn't bring up anything, you may need to change the permissions of the
binary to be executable, i.e. `chmod 755 /path/to/protoc`.

The commands for these steps are something like the following:

```sh
$ mkdir ~/Downloads/protoc-3.2
$ cd ~/Downloads/protoc-3.2

#### OSX
$ wget https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-osx-x86_64.zip
$ unzip protoc-3.2.0-osx-x86_64.zip

#### Linux
$ wget https://github.com/google/protobuf/releases/download/v3.2.0/protoc-3.2.0-linux-x86_64.zip
$ unzip protoc-3.2.0-linux-x86_64.zip

$ sudo cp bin/protoc /usr/local/bin/protoc
$ sudo chmod 755 /usr/local/bin/protoc
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
