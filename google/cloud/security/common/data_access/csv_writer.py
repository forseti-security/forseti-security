# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Writes the csv files for upload to Cloud SQL."""
from contextlib import contextmanager
import os
import tempfile

import unicodecsv as csv

from google.cloud.security.common.data_access.errors import CSVFileError


APPENGINE_FIELDNAMES = [
    'project_id',
    'name',
    'app_id',
    'dispatch_rules',
    'auth_domain',
    'location_id',
    'code_bucket',
    'default_cookie_expiration',
    'serving_status',
    'default_hostname',
    'default_bucket',
    'iap',
    'gcr_domain',
    'raw_application'
]

APPENGINE_SERVICES_FIELDNAMES = [
    'project_id',
    'app_id',
    'service_id',
    'service'
]

APPENGINE_VERSIONS_FIELDNAMES = [
    'project_id',
    'app_id',
    'service_id',
    'version_id',
    'version'
]

APPENGINE_INSTANCES_FIELDNAMES = [
    'project_id',
    'app_id',
    'service_id',
    'version_id',
    'instance_id',
    'instance'
]

BACKEND_SERVICES_FIELDNAMES = [
    'id',
    'project_id',
    'affinity_cookie_ttl_sec',
    'backends',
    'cdn_policy',
    'connection_draining',
    'creation_timestamp',
    'description',
    'enable_cdn',
    'health_checks',
    'iap',
    'load_balancing_scheme',
    'name',
    'port_name',
    'port',
    'protocol',
    'region',
    'session_affinity',
    'timeout_sec',
    'raw_backend_service'
]

BIGQUERY_DATASET_FIELDNAMES = [
    'project_id',
    'dataset_id',
    'access_domain',
    'access_user_by_email',
    'access_special_group',
    'access_group_by_email',
    'role',
    'access_view_project_id',
    'access_view_table_id',
    'access_view_dataset_id',
    'raw_access_map'
]

BUCKETS_ACL_FIELDNAMES = [
    'bucket',
    'domain',
    'email',
    'entity',
    'entity_id',
    'acl_id',
    'kind',
    'project_team',  # TODO: flatten this
    'role',
    'bucket_acl_selflink',
    'raw_bucket_acl'
]

# TODO: Add pydoc to describe the mapping of the custom field naming
# to the field names in the resource objects.
# https://cloud.google.com/storage/docs/json_api/v1/buckets#resource
BUCKETS_FIELDNAMES = [
    'project_number',
    'bucket_id',
    'bucket_name',
    'bucket_kind',
    'bucket_storage_class',
    'bucket_location',
    'bucket_create_time',
    'bucket_update_time',
    'bucket_selflink',
    'bucket_lifecycle_raw',
    'raw_bucket'
]

CLOUDSQL_INSTANCES_FIELDNAMES = [
    'project_number',
    'name',
    'project',
    'backend_type',
    'connection_name',
    'current_disk_size',
    'database_version',
    'failover_replica_available',
    'failover_replica_name',
    'instance_type',
    'ipv6_address',
    'kind',
    'master_instance_name',
    'max_disk_size',
    'on_premises_configuration_host_port',
    'on_premises_configuration_kind',
    'region',
    'replica_configuration',
    'replica_names',
    'self_link',
    'server_ca_cert',
    'service_account_email_address',
    'settings_activation_policy',
    'settings_authorized_gae_applications',
    'settings_availability_type',
    'settings_backup_configuration_binary_log_enabled',
    'settings_backup_configuration_enabled',
    'settings_backup_configuration_kind',
    'settings_backup_configuration_start_time',
    'settings_crash_safe_replication_enabled',
    'settings_data_disk_size_gb',
    'settings_data_disk_type',
    'settings_database_flags',
    'settings_database_replication_enabled',
    'settings_ip_configuration_ipv4_enabled',
    'settings_ip_configuration_require_ssl',
    'settings_kind',
    'settings_labels',
    'settings_location_preference_follow_gae_application',
    'settings_location_preference_kind',
    'settings_location_preference_zone',
    'settings_maintenance_window',
    'settings_pricing_plan',
    'settings_replication_type',
    'settings_settings_version',
    'settings_storage_auto_resize',
    'settings_storage_auto_resize_limit',
    'settings_tier',
    'state',
    'suspension_reason',
    'raw_cloudsql_instance',
]

CLOUDSQL_IPADDRESSES_FIELDNAMES = [
    'project_number',
    'instance_name',
    'type',
    'ip_address',
    'time_to_retire',
]

CLOUDSQL_IPCONFIGURATION_AUTHORIZEDNETWORKS_FIELDNAMES = [
    'project_number',
    'instance_name',
    'kind',
    'name',
    'value',
    'expiration_time',
]

FIREWALL_RULES_FIELDNAMES = [
    'firewall_rule_id',
    'project_id',
    'firewall_rule_name',
    'firewall_rule_description',
    'firewall_rule_kind',
    'firewall_rule_network',
    'firewall_rule_priority',
    'firewall_rule_direction',
    'firewall_rule_source_ranges',
    'firewall_rule_destination_ranges',
    'firewall_rule_source_tags',
    'firewall_rule_target_tags',
    'firewall_rule_source_service_accounts',
    'firewall_rule_target_service_accounts',
    'firewall_rule_allowed',
    'firewall_rule_denied',
    'firewall_rule_self_link',
    'firewall_rule_create_time',
    'raw_firewall_rule'
]

FOLDER_IAM_POLICIES_FIELDNAMES = [
    'folder_id',
    'role',
    'member_type',
    'member_name',
    'member_domain'
]

FOLDERS_FIELDNAMES = [
    'folder_id',
    'name',
    'display_name',
    'lifecycle_state',
    'parent_type',
    'parent_id',
    'raw_folder',
    'create_time',
]

RAW_FOLDER_IAM_POLICIES_FIELDNAMES = [
    'folder_id',
    'iam_policy'
]

FORWARDING_RULES_FIELDNAMES = [
    'id',
    'project_id',
    'creation_timestamp',
    'name',
    'description',
    'region',
    'ip_address',
    'ip_protocol',
    'port_range',
    'ports', # json list
    'target',
    'load_balancing_scheme',
    'subnetwork',
    'network',
    'backend_service',
    'raw_forwarding_rule',
]

GROUP_MEMBERS_FIELDNAMES = [
    'group_id',
    'member_kind',
    'member_role',
    'member_type',
    'member_status',
    'member_id',
    'member_email',
    'raw_member'
]

GROUPS_FIELDNAMES = [
    'group_id',
    'group_email',
    'group_kind',
    'direct_member_count',
    'raw_group'
]

INSTANCES_FIELDNAMES = [
    'id',
    'project_id',
    'can_ip_forward',
    'cpu_platform',
    'creation_timestamp',
    'description',
    'disks',
    'machine_type',
    'metadata',
    'name',
    'network_interfaces',
    'scheduling',
    'service_accounts',
    'status',
    'status_message',
    'tags',
    'zone',
    'raw_instance',
]

INSTANCE_GROUPS_FIELDNAMES = [
    'id',
    'project_id',
    'creation_timestamp',
    'description',
    'instance_urls',
    'name',
    'named_ports',
    'network',
    'region',
    'size',
    'subnetwork',
    'zone',
    'raw_instance_group',
]

INSTANCE_TEMPLATES_FIELDNAMES = [
    'id',
    'project_id',
    'creation_timestamp',
    'description',
    'name',
    'properties',
    'raw_instance_template',
]

INSTANCE_GROUP_MANAGERS_FIELDNAMES = [
    'id',
    'project_id',
    'base_instance_name',
    'creation_timestamp',
    'current_actions',
    'description',
    'instance_group',
    'instance_template',
    'name',
    'named_ports',
    'region',
    'target_pools',
    'target_size',
    'zone',
    'raw_instance_group_manager',
]

ORG_IAM_POLICIES_FIELDNAMES = [
    'org_id',
    'role',
    'member_type',
    'member_name',
    'member_domain'
]

ORGANIZATIONS_FIELDNAMES = [
    'org_id',
    'name',
    'display_name',
    'lifecycle_state',
    'raw_org',
    'creation_time',
]

VIOLATION_FIELDNAMES = [
    'resource_id',
    'resource_type',
    'rule_index',
    'rule_name',
    'new_violation',
    'violation_type',
    'violation_data'
]

PROJECT_IAM_POLICIES_FIELDNAMES = [
    'project_number',
    'role',
    'member_type',
    'member_name',
    'member_domain'
]

PROJECTS_FIELDNAMES = [
    'project_number',
    'project_id',
    'project_name',
    'lifecycle_state',
    'parent_type',
    'parent_id',
    'raw_project',
    'create_time'
]

RAW_BUCKETS_FIELDNAMES = [
    'project_number',
    'buckets'
]

RAW_ORG_IAM_POLICIES_FIELDNAMES = [
    'org_id',
    'iam_policy'
]

RAW_PROJECT_IAM_POLICIES_FIELDNAMES = [
    'project_number',
    'iam_policy'
]

SERVICE_ACCOUNTS_FIELDNAMES = [
    'project_id',
    'name',
    'email',
    'oauth2_client_id',
    'account_keys',
    'raw_service_account'
]

CSV_FIELDNAME_MAP = {
    'appengine': APPENGINE_FIELDNAMES,
    'appengine_services': APPENGINE_SERVICES_FIELDNAMES,
    'appengine_versions': APPENGINE_VERSIONS_FIELDNAMES,
    'appengine_instances': APPENGINE_INSTANCES_FIELDNAMES,

    'backend_services': BACKEND_SERVICES_FIELDNAMES,

    'bigquery_datasets': BIGQUERY_DATASET_FIELDNAMES,

    'buckets': BUCKETS_FIELDNAMES,
    'buckets_acl': BUCKETS_ACL_FIELDNAMES,
    'raw_buckets': RAW_BUCKETS_FIELDNAMES,

    'cloudsql_instances': CLOUDSQL_INSTANCES_FIELDNAMES,
    'cloudsql_ipaddresses': CLOUDSQL_IPADDRESSES_FIELDNAMES,
    'cloudsql_ipconfiguration_authorizednetworks': \
        CLOUDSQL_IPCONFIGURATION_AUTHORIZEDNETWORKS_FIELDNAMES,

    'firewall_rules': FIREWALL_RULES_FIELDNAMES,

    'folder_iam_policies': FOLDER_IAM_POLICIES_FIELDNAMES,
    'folders': FOLDERS_FIELDNAMES,
    'raw_folder_iam_policies': RAW_FOLDER_IAM_POLICIES_FIELDNAMES,

    'forwarding_rules': FORWARDING_RULES_FIELDNAMES,

    'group_members': GROUP_MEMBERS_FIELDNAMES,
    'groups': GROUPS_FIELDNAMES,

    'instances': INSTANCES_FIELDNAMES,
    'instance_groups': INSTANCE_GROUPS_FIELDNAMES,
    'instance_templates': INSTANCE_TEMPLATES_FIELDNAMES,
    'instance_group_managers': INSTANCE_GROUP_MANAGERS_FIELDNAMES,

    'org_iam_policies': ORG_IAM_POLICIES_FIELDNAMES,
    'organizations': ORGANIZATIONS_FIELDNAMES,
    'raw_org_iam_policies': RAW_ORG_IAM_POLICIES_FIELDNAMES,

    'project_iam_policies': PROJECT_IAM_POLICIES_FIELDNAMES,
    'projects': PROJECTS_FIELDNAMES,
    'raw_project_iam_policies': RAW_PROJECT_IAM_POLICIES_FIELDNAMES,

    'service_accounts': SERVICE_ACCOUNTS_FIELDNAMES,

    'violations': VIOLATION_FIELDNAMES,
}


@contextmanager
def write_csv(resource_name, data, write_header=False):
    """Start the csv writing flow.

    Args:
        resource_name (str): The resource name.
        data (iterable): An iterable of data to be written to csv.
        write_header (bool): If True, write the header in the csv file.

    Yields:
       object: The CSV temporary file pointer.

    Raises:
        CSVFileError: If there was an error writing the CSV file.
    """
    csv_file = tempfile.NamedTemporaryFile(delete=False)
    try:
        writer = csv.DictWriter(csv_file, doublequote=False, escapechar='\\',
                                quoting=csv.QUOTE_NONE,
                                fieldnames=CSV_FIELDNAME_MAP[resource_name])
        if write_header:
            writer.writeheader()

        for i in data:
            writer.writerow(i)

        # This must be closed before returned for loading.
        csv_file.close()
        yield csv_file

        # Remove the csv file after loading.
        os.remove(csv_file.name)
    except (IOError, OSError, csv.Error) as e:
        raise CSVFileError(resource_name, e)
