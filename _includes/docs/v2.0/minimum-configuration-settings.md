To run Forseti, you'll need to set up your configuration file. Edit
the [forseti_conf_server.yaml sample](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/configs/server/forseti_conf_server.yaml.sample)
file and save it as `forseti_conf_server.yaml`.

You will also need to edit, at a minimum, the following variables in the config file:

* `root_resource_id`
  * **Description**: Root resource to start crawling from.
  * **Valid values**: String, the format of the String is `<resource_type>/<resource_id>`.
  * **Example values**: `organizations/12345677890`.

* `domain_super_admin_email`
  * **Description**: G Suite super admin email.
  * **Valid values**: String.
  * **Example values**: `my_gsuite_admin@my_domain.com`.

* `api_quota`
  * **Description**: The maximum calls we can make to each API per second. This is lower than
  the max allowed API quota to allow space for retries.
  * `max_calls`
    * **Description**: Maximum calls we can make to the API.
    * **Valid values**: Integer.
    * **Example values**: `1`, `2`, `100`.
  * `period`
    * **Description**: What is the period of the max_calls (in seconds).
    * **Valid values**: Float.
    * **Example values**: `1.0`, `1.2`.

* `retention_days`
  * **Description**: Number of days to retain inventory data, -1 : (default) keep all previous data
  forever.
  * **Valid values**: Integer.
  * **Example values**: `-1`, `5`, `10`.
