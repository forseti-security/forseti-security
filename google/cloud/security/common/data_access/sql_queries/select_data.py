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

"""SQL queries to select data from snapshot tables."""

RECORD_COUNT = """
    SELECT COUNT(*) FROM {0}_{1};
"""

PROJECT_IDS = """
    SELECT project_id from projects_{0};
"""

PROJECT_NUMBERS = """
    SELECT project_number from projects_{0};
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

PROJECT_IAM_POLICIES_RAW = """
    SELECT p.project_number, p.project_id, p.project_name, p.lifecycle_state,
    p.parent_type, p.parent_id, i.iam_policy
    FROM projects_{0} p INNER JOIN raw_project_iam_policies_{1} i
    ON p.project_number = i.project_number
    ORDER BY p.project_id
"""

ORG_IAM_POLICIES = """
    SELECT org_id, iam_policy
    FROM raw_org_iam_policies_{0}
"""

LATEST_SNAPSHOT_TIMESTAMP = """
    SELECT max(cycle_timestamp) FROM snapshot_cycles
"""

GROUP_IDS = """
    SELECT group_id from groups_{0};
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

BUCKETS_BY_PROJECT_ID = """
    SELECT bucket_name
    FROM buckets_{0}
    WHERE project_number = {1};
"""
