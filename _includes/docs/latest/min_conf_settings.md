To run Forseti, you'll need to set up your configuration file. Edit
the [forseti_conf_server.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/2.0-dev/configs/forseti_conf_server.yaml.sample)
file and save it as `forseti_conf_server.yaml`.

You will also need to edit, at a minimum, the following variables in the config file:

* `root_resource_id`
  * **Description**:  Root resource to start crawling from, formatted as <resource_type>/<resource_id>
  * **Example value**: "organizations/12345677890"
* `domain_super_admin_email`
  * **Description**:  G Suite super admin email
* `api_quota`
  * **Description**:   The maximum calls we can make to each of the API per second. We are not using the max allowed API quota because we wanted to include some rooms for retries.
* `retention_days`
  * **Description**:  Number of days to retain inventory data, -1 : (default) keep all previous data forever.