To run Forseti, you'll need to set up your configuration file. Please see the 
[detailed guide](https://forsetisecurity.org/docs/latest/setup/install/index.html) to
get a default installation of Forseti setup that can be used in production 
environment. 

Please see the optional settings below to customize your inventory. View the 
full list of inputs [here](https://github.com/forseti-security/terraform-google-forseti#inputs)
to see all of the available options and default values.

You must set `composite_root_resources` variable in your `main.tf` if you want 
to run Forseti on a non-organizational root, or one or more resources from GCP
resource hierarchy (organizations, folders and projects) in any combination.

**NOTE:** The `composite_root_resources` configuration does not support G Suite 
and Explain at this time.

* `composite_root_resources`
  * **Description**: A list of root resources that Forseti will monitor. Can 
    contain one or more resources from the GCP Resource Hierarchy
    in any combination.
    https://cloud.google.com/resource-manager/docs/cloud-platform-resource-hierarchy

    The IAM policy for all resources must grant the appropriate
    [IAM permissions]({% link _docs/latest/concepts/service-accounts.md %}#the-server-service-account)
    to the Forseti service account before they can be included in the inventory.

    Resources can exist in multiple organizations.
  * **Valid values**: List of Strings. The format for each string is 
    `<resource_type>/<resource_id>`.
  * **Example values**: `organizations/5678901234`, `folders/12345677890` and 
    `projects/9876543210`.

* `gsuite_admin_email`
  * **Description**: G Suite administrator email address to match your Forseti
    installation.
  * **Valid values**: String.
  * **Example values**: `my_gsuite_admin@my_domain.com`.

Additional configuration settings allow you to finely tune the inventory
process for your organization. The default values are setup based on the
default quota that all organizations get in Google Cloud Platform and to ensure
the greatest breadth of resources and policies are covered by the inventory.

* API Quota:
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
  * Max calls:
    * **Description**: Maximum calls we can make to the API for a given period 
      of time. For example, maximum calls that can be made to the Admin API can 
      be configured by setting `admin_max_calls` variable in your `main.tf`. 
    * **Valid values**: String.
    * **Example values**: `"1"`, `"2"`, `"100"`.
  * Period:
    * **Description**: The period of max calls for the various APIs. It is 
      measured in seconds. For example, the period of max calls for the Admin 
      API can be configured by setting `admin_period` variable in your 
      `main.tf`.
    * **Valid values**: String.
    * **Example values**: `"1.0"`, `"1.2"`.
  * Disable Polling:
    * **Description**: Specifies that this API should not be called by the
      inventory crawler. This can be used to disable APIs with low QPS for
      resources that are not important or used by your organization in order to
      speed up the time it takes to complete an inventory snapshot. For example,
      you can disable polling to the Admin API by setting 
      `admin_disable_polling` variable to `"true"` in your `main.tf`. 
    * **Valid values**: Boolean.
    * **Example values**: `"true"`, `"false"`.

* `inventory_retention_days`
  * **Description**: Number of days to retain inventory data, -1 : (default)
    keep all previous data forever.
  * **Valid values**: String.
  * **Example values**: `"-1"`, `"5"`, `"10"`.

* Forseti uses [Cloud Asset Inventory](https://cloud.google.com/asset-inventory/docs/overview) (CAI).
  Below are the Forseti-CAI settings that can be customized.
  * `bucket_cai_lifecycle_age`
    * **Description**: GCS CAI lifecycle age value
    * **Valid values**: String.
    * **Example values**: `"14"`
  * `bucket_cai_location`
    * **Description**: GCS CAI storage bucket location
    * **Valid values**: String.
    * **Example values**: `"us-central1"`
  * `cai_api_timeout`
    * **Description**: Timeout in seconds to wait for the exportAssets API to 
      return success.
    * **Valid values**: String.
    * **Example values**: `"3600"`
  * `enable_cai_bucket`
    * **Description**: Create a GCS bucket for CAI exports
    * **Valid values**: String.
    * **Example values**: `"true"`
  

Saving changes:
  1. Save the changes to `main.tf` file.
  1. Run command `terraform plan` to see the infrastructure plan. 
  1. Run command `terraform apply` to apply the infrastructure build.
