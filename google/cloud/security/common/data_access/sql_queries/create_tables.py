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
        `backendType` varchar(255) DEFAULT NULL,
        `connectionName` varchar(255) DEFAULT NULL,
        `currentDiskSize` bigint DEFAULT NULL,
        `databaseVersion` varchar(255) DEFAULT NULL,
        `failoverReplica_available` varchar(255) DEFAULT NULL, 
        `failoverReplica_name` varchar(255) DEFAULT NULL,
        `instanceType` varchar(255) DEFAULT NULL,
        `ipv6Address` varchar(255) DEFAULT NULL,
        `kind` varchar(255) DEFAULT NULL,
        `masterInstanceName` varchar(255) DEFAULT NULL,
        `maxDiskSize` bigint DEFAULT NULL,
        `onPremisesConfiguration_hostPort` varchar(255) DEFAULT NULL,
        `onPremisesConfiguration_kind` varchar(255) DEFAULT NULL,
        `region` varchar(255) DEFAULT NULL,
        `replicaConfiguration` json DEFAULT NULL,
        `replicaNames` json DEFAULT NULL,
        `selfLink` varchar(255) DEFAULT NULL,
        `serverCaCert` json DEFAULT NULL,
        `serviceAccountEmailAddress` varchar(255) DEFAULT NULL,
        `settings_activationPolicy` varchar(255) DEFAULT NULL,
        `settings_authorizedGaeApplications` json DEFAULT NULL,
        `settings_availabilityType` varchar(255) DEFAULT NULL,
        `settings_backupConfiguration_binaryLogEnabled` varchar(255) DEFAULT NULL,
        `settings_backupConfiguration_enabled` varchar(255) DEFAULT NULL,
        `settings_backupConfiguration_kind` varchar(255) DEFAULT NULL,
        `settings_backupConfiguration_startTime` varchar(255) DEFAULT NULL,
        `settings_crashSafeReplicationEnabled` varchar(255) DEFAULT NULL,
        `settings_dataDiskSizeGb` bigint DEFAULT NULL,
        `settings_dataDiskType` varchar(255) DEFAULT NULL,
        `settings_databaseFlags` json DEFAULT NULL,
        `settings_databaseReplicationEnabled` varchar(255) DEFAULT NULL,
        `settings_ipConfiguration_ipv4Enabled` varchar(255) DEFAULT NULL,
        `settings_ipConfiguration_requireSsl` varchar(255) DEFAULT NULL,
        `settings_kind` varchar(255) DEFAULT NULL,
        `settings_labels` json DEFAULT NULL,
        `settings_locationPreference_followGaeApplication` varchar(255) DEFAULT NULL,
        `settings_locationPreference_kind` varchar(255) DEFAULT NULL,
        `settings_locationPreference_zone` varchar(255) DEFAULT NULL,
        `settings_maintenanceWindow` json DEFAULT NULL,
        `settings_pricingPlan` varchar(255) DEFAULT NULL,
        `settings_replicationType` varchar(255) DEFAULT NULL,
        `settings_settingsVersion` bigint DEFAULT NULL,
        `settings_storageAutoResize` varchar(255) DEFAULT NULL,
        `settings_storageAutoResizeLimit` bigint DEFAULT NULL,
        `settings_tier` varchar(255) DEFAULT NULL,
        `state` varchar(255) DEFAULT NULL,
        `suspensionReason` json DEFAULT NULL,
        PRIMARY KEY (id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8;
"""

CREATE_CLOUDSQL_IPADDRESSES_TABLE = """
    CREATE TABLE {0} (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) NOT NULL,    
        `instance_name` varchar(255) DEFAULT NULL,
        `type` varchar(255) DEFAULT NULL,
        `ipAddress` varchar(255) DEFAULT NULL,
        `timeToRetire` datetime DEFAULT NULL,
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
        `expirationTime` datetime DEFAULT NULL,
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
