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

"""SQL queries to create Cloud SQL tables."""

CREATE_BACKEND_SERVICES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_id` varchar(255) DEFAULT NULL,
        `affinity_cookie_ttl_sec` int DEFAULT NULL,
        `backends` json DEFAULT NULL,
        `cdn_policy` json DEFAULT NULL,
        `connection_draining` json DEFAULT NULL,
        `creation_timestamp` datetime DEFAULT NULL,
        `description` varchar(255) DEFAULT NULL,
        `enable_cdn` bool DEFAULT NULL,
        `health_checks` json DEFAULT NULL,
        `iap` json DEFAULT NULL,
        `load_balancing_scheme` varchar(255) DEFAULT NULL,
        `name` varchar(255) DEFAULT NULL,
        `port_name` varchar(255) DEFAULT NULL,
        `port` int DEFAULT NULL,
        `protocol` varchar(255) DEFAULT NULL,
        `region` varchar(255) DEFAULT NULL,
        `session_affinity` varchar(255) DEFAULT NULL,
        `timeout_sec` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_BIGQUERY_DATASETS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_id` varchar(255) DEFAULT NULL,
        `dataset_id` varchar(255) DEFAULT NULL,
        `access_domain` varchar(255) DEFAULT NULL,
        `access_user_by_email` varchar(255) DEFAULT NULL,
        `access_special_group` varchar(255) DEFAULT NULL,
        `access_group_by_email` varchar(255) DEFAULT NULL,
        `role` varchar(255) DEFAULT NULL,
        `access_view_project_id` varchar(255) DEFAULT NULL,
        `access_view_table_id` varchar(255) DEFAULT NULL,
        `access_view_dataset_id` varchar(255) DEFAULT NULL,
        `raw_access_map` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_BUCKETS_ACL_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `bucket` varchar(255) DEFAULT NULL,
        `domain` varchar(255) DEFAULT NULL,
        `email` varchar(255) DEFAULT NULL,
        `entity` varchar(255) DEFAULT NULL,
        `entity_id` varchar(255) DEFAULT NULL,
        `acl_id` varchar(255) DEFAULT NULL,
        `kind` varchar(255) DEFAULT NULL,
        `project_team` json DEFAULT NULL,
        `role` varchar(255) DEFAULT NULL,
        `bucket_acl_selflink` varchar(255) DEFAULT NULL,
        `raw_bucket_acl` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""


CREATE_BUCKETS_ACL_VIOLATIONS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `resource_type` varchar(255) NOT NULL,
        `resource_id` varchar(255) NOT NULL,
        `rule_name` varchar(255) DEFAULT NULL,
        `rule_index` int DEFAULT NULL,
        `violation_type` enum('BUCKET_VIOLATION') NOT NULL,
        `role` varchar(255) DEFAULT NULL,
        `entity` varchar(255) DEFAULT NULL,
        `email` varchar(255) DEFAULT NULL,
        `domain` varchar(255) DEFAULT NULL,
        `bucket` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_BUCKETS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) NOT NULL,
        `bucket_id` varchar(255) DEFAULT NULL,
        `bucket_name` varchar(255) DEFAULT NULL,
        `bucket_kind` varchar(255) DEFAULT NULL,
        `bucket_storage_class` varchar(255) DEFAULT NULL,
        `bucket_location` varchar(255) DEFAULT NULL,
        `bucket_create_time` datetime DEFAULT NULL,
        `bucket_update_time` datetime DEFAULT NULL,
        `bucket_selflink` varchar(255) DEFAULT NULL,
        `bucket_lifecycle_raw` json DEFAULT NULL,
        `raw_bucket` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_CLOUDSQL_ACL_VIOLATIONS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `resource_type` varchar(255) NOT NULL,
        `resource_id` varchar(255) NOT NULL,
        `rule_name` varchar(255) DEFAULT NULL,
        `rule_index` int DEFAULT NULL,
        `violation_type` enum('CLOUD_SQL_VIOLATION') NOT NULL,
        `instance_name` varchar(255) DEFAULT NULL,
        `authorized_networks` varchar(255) DEFAULT NULL,
        `ssl_enabled` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_CLOUDSQL_INSTANCES_TABLE = """
    CREATE TABLE {0} (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) NOT NULL,
        `name` varchar(255) DEFAULT NULL,
        `project` varchar(255) DEFAULT NULL,
        `backend_type` varchar(255) DEFAULT NULL,
        `connection_name` varchar(255) DEFAULT NULL,
        `current_disk_size` bigint DEFAULT NULL,
        `database_version` varchar(255) DEFAULT NULL,
        `failover_replica_available` varchar(255) DEFAULT NULL, 
        `failover_replica_name` varchar(255) DEFAULT NULL,
        `instance_type` varchar(255) DEFAULT NULL,
        `ipv6_address` varchar(255) DEFAULT NULL,
        `kind` varchar(255) DEFAULT NULL,
        `master_instance_name` varchar(255) DEFAULT NULL,
        `max_disk_size` bigint DEFAULT NULL,
        `on_premises_configuration_host_port` varchar(255) DEFAULT NULL,
        `on_premises_configuration_kind` varchar(255) DEFAULT NULL,
        `region` varchar(255) DEFAULT NULL,
        `replica_configuration` json DEFAULT NULL,
        `replica_names` json DEFAULT NULL,
        `self_link` varchar(255) DEFAULT NULL,
        `server_ca_cert` json DEFAULT NULL,
        `service_account_email_address` varchar(255) DEFAULT NULL,
        `settings_activation_policy` varchar(255) DEFAULT NULL,
        `settings_authorized_gae_applications` json DEFAULT NULL,
        `settings_availability_type` varchar(255) DEFAULT NULL,
        `settings_backup_configuration_binary_log_enabled` varchar(255) DEFAULT NULL,
        `settings_backup_configuration_enabled` varchar(255) DEFAULT NULL,
        `settings_backup_configuration_kind` varchar(255) DEFAULT NULL,
        `settings_backup_configuration_start_time` varchar(255) DEFAULT NULL,
        `settings_crash_safe_replication_enabled` varchar(255) DEFAULT NULL,
        `settings_data_disk_size_gb` bigint DEFAULT NULL,
        `settings_data_disk_type` varchar(255) DEFAULT NULL,
        `settings_database_flags` json DEFAULT NULL,
        `settings_database_replication_enabled` varchar(255) DEFAULT NULL,
        `settings_ip_configuration_ipv4_enabled` varchar(255) DEFAULT NULL,
        `settings_ip_configuration_require_ssl` varchar(255) DEFAULT NULL,
        `settings_kind` varchar(255) DEFAULT NULL,
        `settings_labels` json DEFAULT NULL,
        `settings_location_preference_follow_gae_application` varchar(255) DEFAULT NULL,
        `settings_location_preference_kind` varchar(255) DEFAULT NULL,
        `settings_location_preference_zone` varchar(255) DEFAULT NULL,
        `settings_maintenance_window` json DEFAULT NULL,
        `settings_pricing_plan` varchar(255) DEFAULT NULL,
        `settings_replication_type` varchar(255) DEFAULT NULL,
        `settings_settings_version` bigint DEFAULT NULL,
        `settings_storage_auto_resize` varchar(255) DEFAULT NULL,
        `settings_storage_auto_resize_limit` bigint DEFAULT NULL,
        `settings_tier` varchar(255) DEFAULT NULL,
        `state` varchar(255) DEFAULT NULL,
        `suspension_reason` json DEFAULT NULL,
        PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_CLOUDSQL_IPADDRESSES_TABLE = """
    CREATE TABLE {0} (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) NOT NULL,    
        `instance_name` varchar(255) DEFAULT NULL,
        `type` varchar(255) DEFAULT NULL,
        `ip_address` varchar(255) DEFAULT NULL,
        `time_to_retire` datetime DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_CLOUDSQL_IPCONFIGURATION_AUTHORIZEDNETWORKS = """
    CREATE TABLE {0} (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,    
        `project_number` bigint(20) NOT NULL,    
        `instance_name` varchar(255) DEFAULT NULL,
        `kind` varchar(255) DEFAULT NULL,
        `name` varchar(255) DEFAULT NULL,
        `value` varchar(255) DEFAULT NULL,
        `expiration_time` datetime DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_FIREWALL_RULES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `firewall_rule_id` bigint(20) unsigned NOT NULL,
        `project_id` varchar(255) NOT NULL,
        `firewall_rule_name` varchar(255) DEFAULT NULL,
        `firewall_rule_description` varchar(255) DEFAULT NULL,
        `firewall_rule_kind` varchar(255) DEFAULT NULL,
        `firewall_rule_network` varchar(255) DEFAULT NULL,
        `firewall_rule_priority` smallint(5) unsigned,
        `firewall_rule_direction` varchar(255) DEFAULT NULL,
        `firewall_rule_source_ranges` json DEFAULT NULL,
        `firewall_rule_destination_ranges` json DEFAULT NULL,
        `firewall_rule_source_tags` json DEFAULT NULL,
        `firewall_rule_target_tags` json DEFAULT NULL,
        `firewall_rule_allowed` json DEFAULT NULL,
        `firewall_rule_denied` json DEFAULT NULL,
        `firewall_rule_self_link` varchar(255) DEFAULT NULL,
        `firewall_rule_create_time` datetime(3) DEFAULT NULL,
        `raw_firewall_rule` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_FOLDER_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `folder_id` bigint(20) DEFAULT NULL,
        `role` varchar(255) DEFAULT NULL,
        `member_type` varchar(255) DEFAULT NULL,
        `member_name` varchar(255) DEFAULT NULL,
        `member_domain` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_FOLDERS_TABLE = """
    CREATE TABLE `{0}` (
        `folder_id` bigint(20) unsigned NOT NULL,
        `name` varchar(255) NOT NULL,
        `display_name` varchar(255) DEFAULT NULL,
        `lifecycle_state` enum('ACTIVE','DELETE_REQUESTED',
            'DELETED','LIFECYCLE_STATE_UNSPECIFIED') DEFAULT NULL,
        `parent_type` varchar(255) DEFAULT NULL,
        `parent_id` varchar(255) DEFAULT NULL,
        `raw_folder` json DEFAULT NULL,
        `create_time` datetime DEFAULT NULL,
        PRIMARY KEY (`folder_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_FORWARDING_RULES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL,
        `project_id` varchar(255) NOT NULL,
        `creation_timestamp` datetime DEFAULT NULL,
        `name` varchar(255) DEFAULT NULL,
        `description` varchar(255) DEFAULT NULL,
        `region` varchar(255) DEFAULT NULL,
        `ip_address` varchar(255) DEFAULT NULL,
        `ip_protocol` enum('TCP','UDP','ESP','AH','SCTP','ICMP') DEFAULT NULL,
        `port_range` varchar(255) DEFAULT NULL,
        `ports` json DEFAULT NULL,
        `target` varchar(255) DEFAULT NULL,
        `load_balancing_scheme` enum('INTERNAL','EXTERNAL') DEFAULT NULL,
        `subnetwork` varchar(255) DEFAULT NULL,
        `network` varchar(255) DEFAULT NULL,
        `backend_service` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

# TODO: Add a RAW_GROUP_MEMBERS_TABLE.
CREATE_GROUP_MEMBERS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `group_id` varchar(255) DEFAULT NULL,
        `member_kind` varchar(255) DEFAULT NULL,
        `member_role` varchar(255) DEFAULT NULL,
        `member_type` varchar(255) DEFAULT NULL,
        `member_status` varchar(255) DEFAULT NULL,
        `member_id` varchar(255) DEFAULT NULL,
        `member_email` varchar(255) DEFAULT NULL,
        `raw_member` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_GROUPS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `group_id` varchar(255) DEFAULT NULL,
        `group_email` varchar(255) DEFAULT NULL,
        `group_kind` varchar(255) DEFAULT NULL,
        `direct_member_count` bigint(20) DEFAULT NULL,
        `raw_group` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_INSTANCES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_id` varchar(255) DEFAULT NULL,
        `can_ip_forward` bool DEFAULT NULL,
        `cpu_platform` varchar(255) DEFAULT NULL,
        `creation_timestamp` datetime DEFAULT NULL,
        `description` varchar(255) DEFAULT NULL,
        `disks` json DEFAULT NULL,
        `machine_type` varchar(255) DEFAULT NULL,
        `metadata` json DEFAULT NULL,
        `name` varchar(255) DEFAULT NULL,
        `network_interfaces` json DEFAULT NULL,
        `scheduling` json DEFAULT NULL,
        `service_accounts` json DEFAULT NULL,
        `status` varchar(255) DEFAULT NULL,
        `status_message` varchar(255) DEFAULT NULL,
        `tags` json DEFAULT NULL,
        `zone` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_INSTANCE_GROUP_MANAGERS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_id` varchar(255) DEFAULT NULL,
        `base_instance_name` varchar(255) DEFAULT NULL,
        `creation_timestamp` datetime DEFAULT NULL,
        `current_actions` json DEFAULT NULL,
        `description` varchar(255) DEFAULT NULL,
        `instance_group` varchar(255) DEFAULT NULL,
        `instance_template` varchar(255) DEFAULT NULL,
        `name` varchar(255) DEFAULT NULL,
        `named_ports` json DEFAULT NULL,
        `region` varchar(255) DEFAULT NULL,
        `target_pools` json DEFAULT NULL,
        `target_size` int DEFAULT NULL,
        `zone` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_ORG_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `org_id` bigint(20) DEFAULT NULL,
        `role` varchar(255) DEFAULT NULL,
        `member_type` varchar(255) DEFAULT NULL,
        `member_name` varchar(255) DEFAULT NULL,
        `member_domain` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_ORGANIZATIONS_TABLE = """
    CREATE TABLE `{0}` (
        `org_id` bigint(20) unsigned NOT NULL,
        `name` varchar(255) NOT NULL,
        `display_name` varchar(255) DEFAULT NULL,
        `lifecycle_state` enum('LIFECYCLE_STATE_UNSPECIFIED','ACTIVE',
            'DELETE_REQUESTED', 'DELETED') NOT NULL,
        `raw_org` json DEFAULT NULL,
        `creation_time` datetime DEFAULT NULL,
        PRIMARY KEY (`org_id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_PROJECT_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) DEFAULT NULL,
        `role` varchar(255) DEFAULT NULL,
        `member_type` varchar(255) DEFAULT NULL,
        `member_name` varchar(255) DEFAULT NULL,
        `member_domain` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_PROJECT_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) NOT NULL,
        `project_id` varchar(255) NOT NULL,
        `project_name` varchar(255) DEFAULT NULL,
        `lifecycle_state` enum('LIFECYCLE_STATE_UNSPECIFIED','ACTIVE',
            'DELETE_REQUESTED','DELETED') NOT NULL,
        `parent_type` varchar(255) DEFAULT NULL,
        `parent_id` varchar(255) DEFAULT NULL,
        `raw_project` json DEFAULT NULL,
        `create_time` datetime DEFAULT NULL,
        PRIMARY KEY (`id`),
        UNIQUE KEY `project_id_UNIQUE` (`project_id`),
        UNIQUE KEY `project_number_UNIQUE` (`project_number`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_RAW_BUCKETS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) DEFAULT NULL,
        `buckets` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_RAW_FOLDER_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `folder_id` bigint(20) DEFAULT NULL,
        `iam_policy` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_RAW_ORG_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `org_id` bigint(20) DEFAULT NULL,
        `iam_policy` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_RAW_PROJECT_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) DEFAULT NULL,
        `iam_policy` json DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_VIOLATIONS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `resource_type` varchar(255) NOT NULL,
        `resource_id` varchar(255) NOT NULL,
        `rule_name` varchar(255) DEFAULT NULL,
        `rule_index` int DEFAULT NULL,
        `violation_type` enum('UNSPECIFIED','ADDED','REMOVED') NOT NULL,
        `role` varchar(255) DEFAULT NULL,
        `member` varchar(255) DEFAULT NULL,
        PRIMARY KEY (`id`)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""
