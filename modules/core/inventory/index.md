---
permalink: /modules/core/inventory/
---
# Inventory
This is the Inventory component of Forseti Security tool.

## Executing inventory
After running setup.py, as long as your virtualenv is activated, then you can be in
any directory to invoke the console script:

```sh
$ forseti_inventory
```

### Executing inventory to collect GSuite Google Groups

```sh
$ forset_inventory --inventory_groups
--domain_super_admin_email EMAIL_ADDRESS_OF_A_GSUITE_SUPER_ADMIN \
--groups_service_account_key_file PATH_THE_DOWNLOADED_KEY_OF_THE_GROUPS_SERVICE_ACCOUNT
```

Where
* --groups_service_account_key_file: The path to the
  domain-wide-delegation key created for the groups-only service account
  ([details](/docs/common/SERVICE-ACCOUNT.md#create-a-service-account-for-inventorying-of-gsuite-google-groups)).

You can also use the convenience [dev\_inventory.sh script](/scripts) to run forseti\_inventory. Make a copy of dev\_inventory.sh.sample as dev\_inventory.sh, edit the script for the appropriate commandline flags, and invoke the script from the repo root to run inventory.

```sh
$ cd path/to/forseti-security
$ scripts/dev_inventory.sh
```
## Developing on inventory
### Collecting and storing new data with inventory

It's straightforward to add a new resource to inventory for collection. This workflow is designed to be generic across resource types.

1. Define a new table schema for the 'flattened' data you need to store.
Each relevant field of data you retrieve from an API should correspond to a column in the table schema.

2. Define a new table schema for the 'raw data you need to store.
Additionally, we aim to store the raw API data as json to assist troubleshooting.

Once you've completed these steps create a [Pull Request](https://help.github.com/articles/creating-a-pull-request/) ([an example PR](https://github.com/GoogleCloudPlatform/forseti-security/pull/159)).

3. Once the database PR is merged create a [pipeline](/google/cloud/security/inventory/pipelines/) to fetch your data.
This possibly requires adding new API support, and different authentication. If your change does not require adding new API support you can skip step 4.

4. Add your pipeline to [`inventory_loader.py`](/google/cloud_securit/inventory/inventory_loader.py).
Doing this might require protecting the processing of this pipeline with new flags.

5. Flattening the data collected from your API
Data retrieved from the Google Cloud APIs can have nested and repeating children, e.g. JSON.

    ```json
    Example API Data
    {
        "projects": [
          {
            "name": "project1",
            "parent": {
              "type": "organization",
              "id": "888888888888"
            },
            "projectId": "project1",
            "projectNumber": "25621943694",
            "lifecycleState": "ACTIVE",
            "createTime": "2016-10-22T16:57:36.096Z"
          },
          {
            "name": "project2",
            "parent": {
              "type": "organization",
              "id": "888888888888"
            },
            "projectId": "project2",
            "projectNumber": "94226340476",
            "lifecycleState": "ACTIVE",
            "createTime": "2016-11-13T05:32:10.930Z"
          },
        ]
    }
    ```

To store this data in CSV or in a normalized storage system requires flattening the data into rows.

    ```
    Example Transformed (Flattened) Data
    project_number, project_id, project_name, lifecycle_status, parent_type, parent_id, create_time
    25621943694 project1  project1  ACTIVE  organization  888888888888  2016-10-22 16:57:36
    94226340476 project2  project2  ACTIVE  organization  888888888888  2016-11-13 05:32:10
    ```
Here's an example of [flattening the data structure](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/inventory/transform_util.py#L29)

6. Load the flattened data into database table
For an example of steps 3 through 6 see this [PR](https://github.com/GoogleCloudPlatform/forseti-security/pull/165)