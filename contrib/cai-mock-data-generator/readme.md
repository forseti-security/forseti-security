# Supported resource types:
- organization
- folder
- project
- appengine_application
- appengine_service
- appengine_version
- bucket
- bigquery_dataset
- bigquery_table
- compute_firewall_rule
- compute_disk
- compute_snapshot
- service_account

## <a name="allowed-sub-resources"></a> Here are the list of allowed sub resource type you can define per resource type:
- organization
  - folder
  - project
- folder
  - folder
  - project
- project
  - appengine_application (Only one is allowed per project.)
  - bigquery_dataset
  - bucket
  - compute_firewall_rule
  - compute_disk
  - compute_snapshot
  - service_account
- bigquery_dataset
  - bigquery_table
- appengine_application
  - appengine_service
- appengine_service
  - appengine_version
- bucket
  - N/A
- service_account
  - N/A
- bigquery_table
  - N/A

Update `config.yaml` file with organization structure and run `python main.py` 
to generate the cai dump files for IAM and resource.

root_resource_type can either be `organization`, `folder` or `project`.

Note: IAM policies are randomly generated per resource that can have an IAM policy (at least one role/member binding).

# How to configure `config.yaml`

User will need to specify the root_resource_id and root_resource_type as the root resource of the generated mock data.

As for `resource structure`, user will need to specify the count of the resource for each of the resource type.

For example, if you want to generate 10 folders under `organization/123456`, you can update the `config.yaml` file to the following:
```
output_path: '.'
output_file_name_prefix: testing

root_resource_type: organization
root_resource_id: 123456

resource_structure:
  - resource_count: 10
    folder: []
```
If you want to add 5 projects per folder, you can add resource type `project` and the count of the project under `folder`.

The following configuration will generate 10 folders and 50 projects (5 projects per folder).
```
output_path: '.'
output_file_name_prefix: testing

root_resource_type: organization
root_resource_id: 123456

resource_structure:
  - resource_count: 10
    folder:
      - resource_count: 10
        project: []
```

You can add more resource types as long as the structure is correct (i.e. defining 
the [correct sub resource under each of the resources](#allowed-sub-resources))

# Adding a new resource type

- Update data/resource_template.py 
  - ```
    # Add a new CAI resource template for the <NEW_RESOURCE_TYPE> and stub out the important variables.
    # An example would look something similar to the following:
    <NEW_RESOURCE_TYPE> = '''
    {{
        "name":"...",
        "asset_type":"...",
        "resource":{{
            "version":"...",
            "discovery_document_uri":"...",
            "discovery_name":"...",
            "parent":"...",
            "data":{{
                ........
            }}
        }}
    }}
    ```

- Update data/resource.py 
  - ```
    # Add a generate_<NEW_RESOURCE_TYPE> function.
    
    def generate_<NEW_RESOURCE_TYPE>(parent_resource, resource_id=''):
    """Generate <NEW_RESOURCE_TYPE> resource.

    Args:
        parent_resource (Resource): The parent resource.
        resource_id (str): The resource id for this resource.

    Returns:
        Resource: A resource object.
    """
    pass
    
    # Update RESOURCE_GENERATOR_FACTORY variable to include a reference to the function.
    
    RESOURCE_GENERATOR_FACTORY = {
      ...
      <NEW_RESOURCE_TYPE>: generate_<NEW_RESOURCE_TYPE>
    }

    # Update RESOURCE_DEPENDENCY_MAP variable to reflect the correct dependecy of the newly added resource type.
    
    RESOURCE_DEPENDENCY_MAP = {
      ...
      <PARENT_OF_NEW_RESOURCE_TYPE>: [<NEW_RESOURCE_TYPE>]
      <NEW_RESOURCE_TYPE>: []
    }
    
    ```
