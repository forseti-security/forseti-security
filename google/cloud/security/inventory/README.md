# Inventory
This is the Inventory component of Forseti Security tool.

## Pre-requisites
See the [PREREQUISITES](/docs/PREREQUISITES.md)

## How to Run
After running setup.py, as long as your virtualenv is activated, then you can be in any directory to invoke the console script:

```sh
$ forseti_inventory
```

You can also use the convenience [dev_inventory.sh script](/scripts) to run forseti_inventory. Make a copy of dev_inventory.sh.sample as dev_inventory.sh, edit the script for the appropriate commandline flags, and invoke the script from the repo root to run inventory.

```sh
$ cd path/to/forseti-security
$ scripts/dev_inventory.sh
```

## How to Test
Look at the test instruction in this [README].

## How to add a new resource to the inventory

It's straightforward to add a new resource to inventory for collection.
This workflow is designed to be generic across resource types.

The main steps are:

1. Define the database table schema to store the resource data.

2. Create a new pipeline worker to process the new table and the table fieldnames.

3. Write a transformation to flatten the data returned by GCP APIs into a format
that's ingestiable.

Look at this PR for an [end-to-end example loading of a resource].

Step-by-Step:

1. Define a new table schema for the data you need to store in Inventory.
Each field of data should correspond to a column in the table schema.
Additionally, we aim to store the raw API data as json to assist
troubleshooting.  Create a PR for this to be reviewed first before rest of the
code is written.  See [create_tables.py] for examples.

2. Once the database PR is merged, create a pipeline worker for your resource
in [inventory/pipelines].  This pipeline worker will then be installed in
[inventory_loader.py].

3. Get the data from GCP.  [See if the API to get your data already exists.]
If not, it's your chance to contribute a new one.

4. Data from GCP API is not normalized and can not be fitted into the
database table.  You will have to write a function to transform the data.
Please write a [test for this transform function].

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

    Example Transformed (Flattened) Data
    project_number, project_id, project_name, lifecycle_status, parent_type, parent_id, create_time
    25621943694 project1  project1  ACTIVE  organization  888888888888  2016-10-22 16:57:36
    94226340476 project2  project2  ACTIVE  organization  888888888888  2016-11-13 05:32:10
    ```

5. Load the flattened data into database table, with the load_data() in [dao.py].  See this [end-to-end example loading of a resource].
    * Add the new table to CREATE_TABLE_MAP in [dao.py].
    * Use the [csv_writer] to write the API data to CSV.
    * Create a new map in [csv_writer], of the fieldnames that matches the CSV column to the database columns.
    * Add the new map in [csv_writer], to CSV_FIELDNAME_MAP.
    * Call the load_sql_provider to generate the SQL to load the data for your resource.
    * Execute the load data SQL command.

## Tips & Tricks
* It is helpful to use a MySql GUI tool to inspect the table data.

[README]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/README.md#tests
[See if the API to get your data already exists.]: https://github.com/GoogleCloudPlatform/forseti-security/tree/master/google/cloud/security/common/gcp_api
[create_tables.py]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/common/data_access/sql_queries/create_tables.py
[csv_writer]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/common/data_access/csv_writer.py
[dao.py]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/common/data_access/dao.py
[end-to-end example loading of a resource]: https://github.com/GoogleCloudPlatform/forseti-security/pull/26
[existing pipelines]: https://github.com/GoogleCloudPlatform/forseti-security/tree/master/google/cloud/security/inventory/pipelines
[inventory_loader.py]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/inventory/inventory_loader.py
[inventory/pipelines]: https://github.com/GoogleCloudPlatform/forseti-security/tree/master/google/cloud/security/inventory/pipelines
[test for this transform function]: https://github.com/GoogleCloudPlatform/forseti-security/blob/master/tests/inventory/transform_util_test.py
