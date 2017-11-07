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

"""Provides violations map"""

from google.cloud.security.common.data_access import violation_format as vf


VIOLATION_MAP = {
    'violations': vf.format_violation,
    'buckets_acl_violations': vf.format_violation,
    'cloudsql_acl_violations': vf.format_violation,
    'groups_violations': vf.format_groups_violation,
}

VIOLATION_RESOURCES = {
    'ADDED': 'policy_violations',
    'REMOVED': 'policy_violations',
    'BIGQUERY_VIOLATION': 'bigquery_acl_violations',
    'BUCKET_VIOLATION': 'buckets_acl_violations',
    'CLOUD_SQL_VIOLATION': 'cloudsql_acl_violations',
    'FORWARDING_RULE_VIOLATION': 'forwarding_rule_violations',
    'FIREWALL_BLACKLIST_VIOLATION': 'firewall_rule_violations',
    'FIREWALL_MATCHES_VIOLATION': 'firewall_rule_violations',
    'FIREWALL_REQUIRED_VIOLATION': 'firewall_rule_violations',
    'FIREWALL_WHITELIST_VIOLATION': 'firewall_rule_violations',
    'GROUP_VIOLATION': 'groups_violations',
    'IAP_VIOLATION': 'iap_violations',
    'INSTANCE_NETWORK_INTERFACE_VIOLATION': (
        'instance_network_interface_violations'),
}
