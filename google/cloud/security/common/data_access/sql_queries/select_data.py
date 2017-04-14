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

PROJECT_NUMBERS = """
    SELECT project_number from projects_{0};
"""

PROJECT_IAM_POLICIES = """SELECT p.project_number, p.project_id, p.project_name,
    p.lifecycle_state as proj_lifecycle, p.parent_type, p.parent_id,
    pol.role, pol.member_type, pol.member_name, pol.member_domain
    FROM projects_{0} p INNER JOIN project_iam_policies_{1} pol
    ON p.project_number = pol.project_number
    ORDER BY p.project_number, pol.role, pol.member_type,
    pol.member_domain, pol.member_name
"""

ORGANIZATIONS = """SELECT org_id, name, display_name, lifecycle_state,
    creation_time
    FROM organizations_{0}
    ORDER BY display_name
"""

ORGANIZATION_BY_ID = """SELECT org_id, name, display_name,
    lifecycle_state, creation_time
    FROM organizations_{0}
    WHERE org_id = %s
"""

ORG_IAM_POLICIES = """SELECT org_id, iam_policy
    FROM raw_org_iam_policies_{0}
"""

LATEST_SNAPSHOT_TIMESTAMP = """SELECT max(cycle_timestamp)
    FROM snapshot_cycles
"""

GROUP_IDS = """
    SELECT group_id from groups_{0};
"""
