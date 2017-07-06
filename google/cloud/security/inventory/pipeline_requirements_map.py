# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Map of the requirements needed by the inventory pipelines."""

REQUIREMENTS_MAP = {
    'appengine':
        {'module_name': 'load_appengine_pipeline',
         'depends_on': 'projects',
         'api_name': 'appengine_api',
         'dao_name': 'appengine_dao'},
    'backend_services':
        {'module_name': 'load_backend_services_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_api',
         'dao_name': 'backend_service_dao'},
    'bigquery_datasets':
        {'module_name': 'load_bigquery_datasets_pipeline',
         'depends_on': 'projects',
         'api_name': 'bigquery_api',
         'dao_name': 'dao'},
    'buckets':
        {'module_name': 'load_projects_buckets_pipeline',
         'depends_on': 'projects',
         'api_name': 'gcs_api',
         'dao_name': 'project_dao'},
    'buckets_acls':
        {'module_name': 'load_projects_buckets_acls_pipeline',
         'depends_on': 'buckets',
         'api_name': 'gcs_api',
         'dao_name': 'bucket_dao'},
    'cloudsql':
        {'module_name': 'load_projects_cloudsql_pipeline',
         'depends_on': 'projects',
         'api_name': 'cloudsql_api',
         'dao_name': 'cloudsql_dao'},
    'firewall_rules':
        {'module_name': 'load_firewall_rules_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_beta_api',
         'dao_name': 'project_dao'},
    'folders':
        {'module_name': 'load_folders_pipeline',
         'depends_on': 'organizations',
         'api_name': 'crm_v2beta1_api',
         'dao_name': 'dao'},
    'forwarding_rules':
        {'module_name': 'load_forwarding_rules_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_api',
         'dao_name': 'forwarding_rules_dao'},
    'group_members':
        {'module_name': 'load_group_members_pipeline',
         'depends_on': 'groups',
         'api_name': 'admin_api',
         'dao_name': 'dao'},
    'groups':
        {'module_name': 'load_groups_pipeline',
         'depends_on': 'organizations',
         'api_name': 'admin_api',
         'dao_name': 'dao'},
    'instance_group_managers':
        {'module_name': 'load_instance_group_managers_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_api',
         'dao_name': 'instance_group_manager_dao'},
    'instance_groups':
        {'module_name': 'load_instance_groups_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_api',
         'dao_name': 'instance_group_dao'},
    'instance_templates':
        {'module_name': 'load_instance_templates_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_api',
         'dao_name': 'instance_template_dao'},
    'instances':
        {'module_name': 'load_instances_pipeline',
         'depends_on': 'projects',
         'api_name': 'compute_api',
         'dao_name': 'instance_dao'},
    'org_iam_policies':
        {'module_name': 'load_org_iam_policies_pipeline',
         'depends_on': 'organizations',
         'api_name': 'crm_api',
         'dao_name': 'organization_dao'},
    'organizations':
        {'module_name': 'load_orgs_pipeline',
         'depends_on': None,
         'api_name': 'crm_api',
         'dao_name': 'organization_dao'},
    'projects':
        {'module_name': 'load_projects_pipeline',
         'depends_on': 'folders',
         'api_name': 'crm_api',
         'dao_name': 'project_dao'},
    'projects_iam_policies':
        {'module_name': 'load_projects_iam_policies_pipeline',
         'depends_on': 'projects',
         'api_name': 'crm_api',
         'dao_name': 'project_dao'},
}
