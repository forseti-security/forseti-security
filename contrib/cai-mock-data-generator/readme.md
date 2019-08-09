Supported resource types:
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

Here are the list of allowed sub resource type you can define per resource type:
- organization
  - folder
  - project
- folder
  - folder
  - project
- project
  - appengine_application
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
