# Inventory
This is the Inventory component of Forseti Security tool.
  * [Pre-requisites](#pre-requisites)
  * [Running inventory](#running-inventory)
  * [Collecting and storing new data with inventory](#collecting-and-storing-new-data-with-inventory)
  * [Collecting GSuite Google Groups](#collecting-gsuite-google-groups)
  
## Pre-requisites
See the [PREREQUISITES](/docs/prerequisites/README.md) guide.

## Running inventory
After running setup.py, as long as your virtualenv is activated, then you can be in
any directory to invoke the console script:

```sh
$ forseti_inventory
```

You can also use the convenience [dev_inventory.sh script](/scripts) to run
forseti_inventory. Make a copy of dev_inventory.sh.sample
as dev_inventory.sh, edit the script for the appropriate
commandline flags, and invoke the script from the repo root to run inventory.

```sh
$ cd path/to/forseti-security
$ scripts/dev_inventory.sh
```

## Collecting and storing new data with inventory

It's straightforward to add a new resource to inventory for collection. This workflow is designed to be generic across resource types.

1. Define a new table schema for the 'flattended' data you need to store.
Each relevant field of data you retrieve from an API should correspond to a column in the table schema.

2. Define a new table schema for the 'raw data you need to store.
Additionally, we aim to store the raw API data as json to assist troubleshooting.

Once you've completed these steps create a Pull Request ([example](https://github.com/GoogleCloudPlatform/forseti-security/pull/159)).

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

## Collecting GSuite Google Groups
Forseti supports scanning GCP project ACLs for granted users that might be a GSuite Google group. Doing this requires taking special steps on the previously created service account and within the GSuite domain.

If you have an organization id for GCP then you have a Gsuite account. You can administer your GSuite account at [admin.google.com](admin.google.com).

### Enabling checking of GSuite Google Groups
At a high level these things most be done to enable GSuite Google Group support.

  1. [Enable](https://console.cloud.google.com/iam-admin/serviceaccounts/) Domain-Wide Delegation on the previously created service account. More details on this can be found ([here](https://cloud.google.com/appengine/docs/flexible/python/authorizing-apps#google_apps_domain-wide_delegation_of_authority)).
  1. Enable the service account ID for access within the GSuite account with the proper scope.

* Enable the **Admin SDK API**

  ```sh
  $ gcloud beta service-management list enable admin.googleapis.com
  ```
 
### Configuring your installation type
`Inventory` exposes three flags to collecting GSuite groups as part of it's execution. Use of these flags depend on your installation type.

#### GCP installations
You must configure these variables in the [deployment template](/deployment-templates/deploy-forseti.yaml.sample) ([details](/docs/installing/INSTALLING-GCP.md#customize-deployment-templates)

You must load the key into the meta-data server.

Store the created service account keys on the meta-data server for your GCE instance.

 ```sh
 $ gcloud compute instances create <instance-name> --metadata dwd-key=`cat <key-file.json>`
 ```
 
 ##### Configure the GCP deployment template

**INVENTORY_GROUPS**: To enable set this to True.

**DOMAIN_SUPER_ADMIN_EMAIL**: To inventory GSuite Groups requires using domain-wide delegation (DWD). To do this you must specify a super-admin in the GSuite account to impersonate, e.g. bob@mydomain.com

**METADATA_SERVER_DOMAIN_WIDE_DELEGATION_KEY_NAME**: The name of the key/value pair containing the 

#### Local installations

 **--inventory_groups**: By default this flag is set to False or no. You can enable this by just passing the flag.
 
 ```sh
 $ forseti_inventory --inventory_groups
 ```
 
 #### Configure your parameters to inventory_loader
 
 **--domain_super_admin_email**: To inventory GSuite Groups requires using domain-wide delegation (DWD). To do this you must specify a super-admin in the GSuite account to impersonate, e.g. bob@mydomain.com
 
 **--service_account_email**: This normally already required.
 
 **--service_account_credentials_file**: To use DWD you must download the credentials file in `JSON` format and specify the full-path to the file with this flag.
