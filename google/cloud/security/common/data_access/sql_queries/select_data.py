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

"""SQL queries to select data from snapshot tables."""

RECORD_COUNT = """
    SELECT COUNT(*) FROM {0}_{1};
"""

LATEST_SNAPSHOT_TIMESTAMP = """
    SELECT max(cycle_timestamp) FROM snapshot_cycles
"""

PREVIOUS_SNAPSHOT_TIMESTAMP = """
    SELECT max(cycle_timestamp) FROM snapshot_cycles where
    cycle_timestamp < ( SELECT MAX( cycle_timestamp )
        FROM snapshot_cycles )
"""

PROJECT_NUMBERS = """
    SELECT project_number FROM projects_{0};
"""


PROJECT_RAW_ALL = """
    SELECT raw_project FROM projects_{0};
"""

PROJECT_RAW = """
    SELECT raw_project FROM projects_{0} WHERE project_id = %s;
"""

PROJECT_RAW_BY_NUMBER = """
    SELECT raw_project FROM projects_{0} WHERE project_number = %s;
"""

PROJECT_IAM_POLICIES = """
    SELECT p.project_number, p.project_id, p.project_name,
    p.lifecycle_state as proj_lifecycle, p.parent_type, p.parent_id,
    pol.role, pol.member_type, pol.member_name, pol.member_domain
    FROM projects_{0} p INNER JOIN project_iam_policies_{1} pol
    ON p.project_number = pol.project_number
    ORDER BY p.project_number, pol.role, pol.member_type,
    pol.member_domain, pol.member_name
"""

PROJECTS = """
    SELECT project_number, project_id, project_name,
    lifecycle_state, parent_type, parent_id
    FROM projects_{0}
"""

PROJECT_BY_ID = """
    SELECT project_number, project_id, project_name,
    lifecycle_state, parent_type, parent_id
    FROM projects_{0}
    WHERE project_id = %s
"""

PROJECT_BY_NUMBER = """
    SELECT project_number, project_id, project_name,
    lifecycle_state, parent_type, parent_id
    FROM projects_{0}
    WHERE project_number = %s
"""

PROJECT_IAM_POLICIES_RAW = """
    SELECT p.project_number, p.project_id, p.project_name, p.lifecycle_state,
    p.parent_type, p.parent_id, i.iam_policy
    FROM projects_{0} p INNER JOIN raw_project_iam_policies_{1} i
    ON p.project_number = i.project_number
    ORDER BY p.project_id
"""

ORGANIZATIONS = """
    SELECT org_id, name, display_name, lifecycle_state, creation_time
    FROM organizations_{0}
    ORDER BY display_name
"""

ORGANIZATION_BY_ID = """
    SELECT org_id, name, display_name, lifecycle_state, creation_time
    FROM organizations_{0}
    WHERE org_id = %s
"""

ORG_IAM_POLICIES = """
    SELECT org_id, iam_policy
    FROM raw_org_iam_policies_{0}
"""

FIREWALL_RULES = """
    SELECT id, project_id, firewall_rule_create_time, firewall_rule_name,
    firewall_rule_description, firewall_rule_kind, firewall_rule_network,
    firewall_rule_priority, firewall_rule_direction,
    firewall_rule_source_ranges, firewall_rule_destination_ranges,
    firewall_rule_source_tags, firewall_rule_target_tags,
    firewall_rule_source_service_accounts,
    firewall_rule_target_service_accounts, firewall_rule_allowed,
    firewall_rule_denied
    FROM firewall_rules_{0}
    ORDER BY firewall_rule_name
"""

FOLDERS = """
    SELECT folder_id, name, display_name, lifecycle_state, create_time,
    parent_type, parent_id
    FROM folders_{0}
    ORDER BY display_name
"""

FOLDER_BY_ID = """
    SELECT folder_id, name, display_name, lifecycle_state, create_time,
    parent_type, parent_id
    FROM folders_{0}
    WHERE folder_id = %s
"""

FOLDER_IAM_POLICIES = """
    SELECT f.folder_id, f.display_name, f.lifecycle_state,
    f.parent_type, f.parent_id, i.iam_policy
    FROM folders_{0} f INNER JOIN raw_folder_iam_policies_{1} i
    ON f.folder_id = i.folder_id
    ORDER BY f.folder_id
"""

GROUPS = """
    SELECT * FROM groups_{0};
"""

GROUP_IDS = """
    SELECT group_id FROM groups_{0};
"""

GROUP_ID = """
    SELECT group_id
    FROM groups_{}
    WHERE group_email = %s;
"""

GROUP_MEMBERS = """
    SELECT group_id, member_role, member_type, member_id, member_email
    FROM group_members_{}
    WHERE group_id = %s;
"""

BUCKETS = """
    SELECT project_number, bucket_id, bucket_name, bucket_kind, bucket_storage_class,
    bucket_location, bucket_create_time, bucket_update_time, bucket_selflink,
    bucket_lifecycle_raw
    FROM buckets_{0};
"""

RAW_BUCKETS = """
    SELECT bucket_id, raw_bucket FROM buckets_{0}
"""

BUCKETS_BY_PROJECT_ID = """
    SELECT bucket_name
    FROM buckets_{0}
    WHERE project_number = %s;
"""

SELECT_ALL_VIOLATIONS = """
    SELECT * FROM violations_{0};
"""

SELECT_VIOLATIONS_BY_TYPE = """
    SELECT * FROM violations_{0}
    WHERE violation_type = %s;
"""

BACKEND_SERVICES = """
    SELECT id, project_id, creation_timestamp, name, description,
    affinity_cookie_ttl_sec, backends, cdn_policy, connection_draining,
    enable_cdn, health_checks, load_balancing_scheme, port, port_name,
    protocol, region, session_affinity, timeout_sec, iap
    FROM backend_services_{0}
"""

FORWARDING_RULES = """
    SELECT id, project_id, creation_timestamp, name, description, region,
    ip_address, ip_protocol, port_range, ports, target, load_balancing_scheme,
    subnetwork, network, backend_service
    FROM forwarding_rules_{0}
"""

FORWARDING_RULES_BY_PROJECT_ID = """
    SELECT id, project_id, creation_timestamp, name, description, region,
    ip_address, ip_protocol, port_range, ports, target, load_balancing_scheme,
    subnetwork, network, backend_service
    FROM forwarding_rules_{0}
    WHERE project_id = %s
"""

INSTANCES = """
    SELECT id, project_id, creation_timestamp, name, description,
    can_ip_forward, cpu_platform, disks, machine_type, metadata,
    network_interfaces, scheduling, service_accounts, status,
    status_message, tags, zone
    FROM instances_{0}
"""

INSTANCE_GROUPS = """
    SELECT id, project_id, creation_timestamp, name, description,
    instance_urls, named_ports, network, region, size, subnetwork, zone
    FROM instance_groups_{0}
"""

INSTANCE_TEMPLATES = """
    SELECT id, project_id, creation_timestamp, name, description,
    properties
    FROM instance_templates_{0}
"""

INSTANCE_GROUP_MANAGERS = """
    SELECT id, project_id, creation_timestamp, name, description,
    base_instance_name, current_actions, instance_group,
    instance_template, named_ports, region, target_pools, target_size,
    zone
    FROM instance_group_managers_{0}
"""

BIGQUERY_ACLS = """
    SELECT * FROM bigquery_datasets_{0};
"""

BUCKET_ACLS = """
    SELECT bucket, entity, email, domain, role, project_number
    FROM buckets_{0}, buckets_acl_{0}
    WHERE bucket=bucket_name;
"""

CLOUDSQL_INSTANCES = """
    SELECT project_number,
           name,
           settings_ip_configuration_require_ssl
    FROM cloudsql_instances_{0}
"""

CLOUDSQL_ACLS = """
    SELECT project_number, instance_name, value
    FROM cloudsql_ipconfiguration_authorizednetworks_{0}
"""

APPENGINE_APPS = """
    SELECT id, project_id, name, app_id, dispatch_rules, auth_domain,
    location_id, code_bucket, default_cookie_expiration, serving_status,
    default_hostname, default_bucket, iap, gcr_domain, raw_application
    FROM appengine_{0}
"""

SERVICE_ACCOUNTS = """
    SELECT project_id, name, email, oauth2_client_id, account_keys, raw_service_account
    FROM service_accounts_{0}
"""
