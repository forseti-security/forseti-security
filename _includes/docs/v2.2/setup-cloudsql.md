Forseti stores data in Cloud SQL. You can connect to the Cloud SQL instance by
using the Cloud SQL proxy to authenticate to GCP with your Google credentials,
instead of opening up network access to your Cloud SQL instance.
To set up your Cloud SQL instance for Forseti, follow the steps below:

1. Go to the [Google Cloud Platform Console SQL page](https://console.cloud.google.com/sql) and
    follow the steps below to create a new instance:
    1. Select a **MySQL** database engine.
    1. Select a **Second Generation** instance type.
    1. If you see a **Choose use case** page, select the configuration type you want
       based upon whether this is for production or development use.
    1. On the **Create a MySQL Second Generation instance** page, enter an
        **Instance ID** and **Root password**, then select the following
        settings:
        1. **Database version:** MySQL 5.7
        1. **Machine type:** db-n1-standard-1 machine type
        1. **Storage capacity:** 25 GB
    1. Add or modify other database details as you wish.
    1. When you're finished setting up the database, click **Create**.
1. [Create a new user](https://cloud.google.com/sql/docs/mysql/create-manage-users#creating),
    like `forseti_user`,
    with [read/write privileges](https://cloud.google.com/sql/docs/mysql/users#privileges)
    for Forseti to access the database. Don't set a password for the new user.
    This will allow Cloud SQL Proxy to handle authentication to your instance.
1. [Create a new database](https://cloud.google.com/sql/docs/mysql/create-manage-databases#creating_a_database),
   like `forseti_security`.
1. Use the [SQL Proxy](https://cloud.google.com/sql/docs/mysql-connect-proxy#connecting_mysql_client)
    to proxy your connection to your Cloud SQL instance. Your
    INSTANCE_CONNECTION_NAME is the **Instance Connection Name** under
    **Properties** on the Cloud SQL dashboard instance details, in the format "PROJECTID:REGION:INSTANCEID".
    
    If you are using Cloud SDK authentication:

      ```bash
      <path/to/cloud_sql_proxy> -instances=INSTANCE_CONNECTION_NAME=tcp:3306
      ```
    
    If you are using a service account to authenticate (recommended for production environments):
    
      ```bash
      <path/to/cloud_sql_proxy> \
          -instances=<INSTANCE_CONNECTION_NAME>=tcp:3306 \
          -credential_file=<PATH_TO_KEY_FILE>
      ```
    
    For example:
    
      ```bash
      ./cloud_sql_proxy \
          -instances=foo-project-name:us-central1:mysql-instance=tcp:3306 \
          -credential_file=/usr/local/google/home/foo/foo-project-cert-0d152c0e1bc8.json
      ```

1. If you are setting up a development environment, install
[MySQL Workbench](https://dev.mysql.com/downloads/workbench/?utm_source=tuicool).
This is a GUI tool that will make it much easier to view and query the Forseti tables and data.

    1. Connection Name
    1. Hostname: 127.0.0.1
    1. Port: 3306
    1. Username: forseti_user
