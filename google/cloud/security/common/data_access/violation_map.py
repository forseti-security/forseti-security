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

"""Provides violations map"""

# pylint: disable=line-too-long
from google.cloud.security.common.data_access import violation_format as vf
from google.cloud.security.common.data_access.sql_queries import load_data
from google.cloud.security.common.data_access.sql_queries import select_data as sd
# pylint: enable=line-too-long

VIOLATION_MAP = {
    'violations': vf.format_violation,
    'buckets_acl_violations': vf.format_violation,
    'cloudsql_acl_violations': vf.format_violation,
    'groups_violations': vf.format_groups_violation,
}

VIOLATION_INSERT_MAP = {
    'violations': load_data.INSERT_VIOLATION.format,
    'bigquery_acl_violations': load_data.INSERT_VIOLATION.format,
    'buckets_acl_violations': load_data.INSERT_VIOLATION.format,
    'cloudsql_acl_violations': load_data.INSERT_VIOLATION.format,
    'groups_violations': load_data.INSERT_GROUPS_VIOLATION.format
}

VIOLATION_SELECT_MAP = {
    'policy_violations': sd.SELECT_POLICY_VIOLATIONS.format,
    'groups_violations': sd.SELECT_GROUPS_VIOLATIONS.format,
    'bigquery_acl_violations': sd.SELECT_BIGQUERY_ACL_VIOLATIONS.format,
    'buckets_acl_violations': sd.SELECT_BUCKETS_ACL_VIOLATIONS.format,
    'cloudsql_acl_violations': sd.SELECT_CLOUDSQL_VIOLATIONS.format,
}
