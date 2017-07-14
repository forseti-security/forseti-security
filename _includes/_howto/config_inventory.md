To run Forseti Inventory, you'll need to set up your configuration file. Edit
the [forseti_conf.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/forseti_conf.yaml.sample)
file and save it as **forseti_conf.yaml**.

You will also need to edit, at a minimum, the following variables in the config file:

* `db_host`
* `db_user`
* `db_name`

When you're finished making changes, run the following command to update your
`forseti_inventory` configuration:

````
forseti_inventory --config_path path/to/forseti_conf.yaml
````
