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

from google.cloud.security.common.data_access import violation_format as vf
from google.cloud.security.common.data_access.sql_queries import load_data
from google.cloud.security.common.data_access.sql_queries import select_data

VIOLATION_MAP = {
	   'violations': vf.format_policy_violation,
	   'buckets_acl_violations': vf.format_buckets_acl_violation,
	   'cloudsql_acl_violations': vf.format_cloudsql_acl_violation,
}

VIOLATION_INSERT_MAP = {
	   'violations': load_data.INSERT_VIOLATION.format,
	   'buckets_acl_violations': load_data.INSERT_BUCKETS_ACL_VIOLATION.format,
	   'cloudsql_acl_violations':\
	          load_data.INSERT_CLOUDSQL_ACL_VIOLATION.format
}

VIOLATION_SELECT_MAP = {
    'violations': select_data.SELECT_VIOLATIONS.format,
    'buckets_acl_violations': select_data.SELECT_BUCKETS_ACL_VIOLATIONS.format,
}
