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

CREATE_RAW_PROJECT_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) DEFAULT NULL,
        `iam_policy` json DEFAULT NULL,
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

CREATE_RAW_ORG_IAM_POLICIES_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `org_id` bigint(20) DEFAULT NULL,
        `iam_policy` json DEFAULT NULL,
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

# TODO: Add a RAW_GROUP_MEMBERS_TABLE.

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

CREATE_RAW_BUCKETS_TABLE = """
    CREATE TABLE `{0}` (
        `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
        `project_number` bigint(20) DEFAULT NULL,
        `buckets` json DEFAULT NULL,
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
