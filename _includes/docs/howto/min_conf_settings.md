To run Forseti, you'll need to set up your configuration file. Edit
the [forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
file and save it as `forseti_conf.yaml`.

You will also need to edit, at a minimum, the following variables in the config file:

* `db_host`: If using Cloud SQL Proxy, this is usually "127.0.0.1".
* `db_user`: The database user you created. If you deployed using Deployment Manager, the default value is "root".
* `db_name`: The name of the database you created in the Cloud SQL instance. If you deployed using Deployment Manager, the default value is "forseti_security".
