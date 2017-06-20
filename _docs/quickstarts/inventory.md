---
title: Inventory
order: 002
---
# Inventory
Inventory collects GCP resource data and stores it in a database so Forseti can perform other operations (e.g. security scans and enforcement).

## Executing the inventory loader
After you install Forseti, you can access the Inventory tool with the command below. If you installed Forseti in a virtualenv, remember to activate the virtualenv first.

```sh
$ forseti_inventory
```

### Executing inventory to collect GSuite Google Groups

The `--inventory_groups` is an optional flag. If you provide it as an argument, it will instruct `forseti_inventory` to read your GSuite Google Groups information.

```sh
$ forset_inventory --inventory_groups \
  --domain_super_admin_email EMAIL_ADDRESS_OF_A_GSUITE_SUPER_ADMIN \
  --groups_service_account_key_file PATH_THE_DOWNLOADED_KEY_OF_THE_GROUPS_SERVICE_ACCOUNT
```

Where
* --groups_service_account_key_file: The path to the
  domain-wide-delegation key created for the groups-only service account
  ([details]({{ site.baseurl }}{% link common/service_accounts.md %}).

## Collecting and storing new data with inventory

This is the generic workflow for adding new GCP resource types to Forseti Inventory.

1. Define a new table schema for the "flattened" data you need to store.
    Each relevant field of data you retrieve from an API should correspond to a column in the table schema.

2. Define a new table schema for the "raw data" you need to store.
    We store the raw API data as json to assist troubleshooting.

3. Create a [Pull Request](https://help.github.com/articles/creating-a-pull-request/)
  ([an example PR](https://github.com/GoogleCloudPlatform/forseti-security/pull/159)).

4. Once the database PR is merged, create a [pipeline](https://github.com/GoogleCloudPlatform/forseti-security/tree/master/google/cloud/security/inventory/pipelines)
to fetch your data. You might also need to extend Forseti's API support and
different authentication. If your change does not require adding new API
support you can skip step 4.

5. Add your pipeline to [`inventory_loader.py`](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/inventory/inventory_loader.py).
    You might need to create additional commandline flags to configure your pipeline.

6. Flatten the data collected from your API.
    Data retrieved from the Google Cloud APIs can have nested and repeating children, e.g. JSON.

    ```json
    /* Example API Data */
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

    ```sh
    # Example Transformed (Flattened) Data
    project_number, project_id, project_name, lifecycle_status, parent_type, parent_id, create_time
    25621943694 project1  project1  ACTIVE  organization  888888888888  2016-10-22 16:57:36
    94226340476 project2  project2  ACTIVE  organization  888888888888  2016-11-13 05:32:10
    ```

    Here's an example of [flattening the data structure](https://github.com/GoogleCloudPlatform/forseti-security/blob/master/google/cloud/security/inventory/pipelines/load_projects_pipeline.py#L32)

6. Load the flattened data into database table.
     For an example of steps 3 through 6 see this [PR](https://github.com/GoogleCloudPlatform/forseti-security/pull/165)
