To run Forseti, you'll need to set up your configuration file. Edit
the [forseti_conf_server.yaml sample](https://github.com/forseti-security/forseti-security/blob/master/configs/server/forseti_conf_server.yaml.sample)
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

* `cai`
  * **Description**: Cloud Asset Inventory (CAI) can be enabled if the level
   is `organization` by providing values for the attributes below.
  * `enabled`
    * **Description**: Specifies whether CAI is enabled or not.
    * **Valid values**: Boolean.
    * **Example values**: `true`, `false`.
  * `gcs_path`
    * **Description**: GCS Path of the newly created bucket to be used for 
    CAI exports.
    * **Valid values**: Location of the bucket. Bucket needs to be in the
    Forseti project.
    * **Example values**: gs://my_cai_export_bucket
