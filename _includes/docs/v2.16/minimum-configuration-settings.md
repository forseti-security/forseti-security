To run Forseti, you'll need to set up your configuration file. Edit
the [forseti_conf_server.yaml sample](https://github.com/forseti-security/forseti-security/blob/master/configs/server/forseti_conf_server.yaml.sample)
file and save it as `forseti_conf_server.yaml`.

You will also need to edit, at a minimum, the following variables in the config
file:

You must set ONLY one of root_resource_id or composite_root_resources in your
configuration. Defining both will cause Forseti to exit with an error.

*NOTE*: The composite_root_resources configuration does not support gsuite and
Explain at this time.

**Either**

* `root_resource_id`
  * **Description**: Root resource to start crawling from.
  * **Valid values**: String, the format is `<resource_type>/<resource_id>`.
  * **Example values**: `organizations/12345677890`.

* `domain_super_admin_email`
  * **Description**: G Suite super admin email.
  * **Valid values**: String.
  * **Example values**: `my_gsuite_admin@my_domain.com`.

**OR**

* `composite_root_resources`
  * **Description**: List of all resources to include in a single Forseti
    inventory. Can contain one or more resources from the GCP Resource Hierarchy
    in any combination.
    https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy

    The IAM policy for all resources must grant the appropriate
    [IAM permissions]({% link _docs/v2.16/concepts/service-accounts.md %}#the-server-service-account)
    to the Forseti service account before they can be included in the inventory.

    Resources can exist in multiple organizations.
  * **Valid values**: List of Strings,
    the format for each string is `<resource_type>/<resource_id>`.
  * **Example values**: `folders/12345677890`, `projects/9876543210`,
    `organizations/5678901234`

Additional configuration settings allow you to finely tune the inventory
process for your organization. The default values are setup based on the
default quota that all organizations get in Google Cloud Platform and to ensure
the greatest breadth of resources and policies are covered by the inventory.

* `api_quota`
  * **Description**: The maximum calls we can make to each API per second. This
    should be about 10% lower than the max allowed API quota to allow space for
    retries.

    While most APIs will list their quota as calls per 100 seconds,
    the rate limiter used by Forseti will be most accurate over a 1 to 2
    second time period.

    For example, to calculate the values for max_calls and period for a
    theoretical API that has a quota of 500 calls per 100 seconds, use the
    following formula:

    max_calls = 500/100 = 5 (5 calls per period)

    period = 1.0/.9 = 1.11 rounded to nearest tenth = 1.1 (10% overhead)

    The default values are based on the default quota all projects get for GCP
    APIs, however large organizations may request quota increases through the
    cloud console to reduce the time it takes to complete an inventory.
  * `max_calls`
    * **Description**: Maximum calls we can make to the API for a give period of
      time.
    * **Valid values**: Integer.
    * **Example values**: `1`, `2`, `100`.
  * `period`
    * **Description**: What is the period over which max_calls is measured (in
      seconds).
    * **Valid values**: Float.
    * **Example values**: `1.0`, `1.2`.
  * `disable_polling`
    * **Description**: Specifies that this API should not be called by the
      inventory crawler. This can be used to disable APIs with low QPS for
      resources that are not important or used by your organization in order to
      speed up the time it takes to complete an inventory snapshot.
    * **Valid values**: Boolean.
    * **Example values**: `true`, `false`.

* `retention_days`
  * **Description**: Number of days to retain inventory data, -1 : (default)
    keep all previous data forever.
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
      CAI exports. Bucket needs to be in the Forseti project.
    * **Valid values**: String. Location of the bucket, must start with gs://.
    * **Example values**: `gs://my_cai_export_bucket`
  * `asset_types`
    * **Description**: Optional list of asset types to restrict the Cloud
      Asset inventory API to, when exporting data for your resources. If not
      specified, all supported asset types will be included in the inventory.
      The full list of supported asset types is available in the public
      documentation:
      https://cloud.google.com/resource-manager/docs/cloud-asset-inventory/overview
    * **Valid values**: List.
    * **Example values**: `google.cloud.resourcemanager.Organization`,
      `google.compute.Instance`
