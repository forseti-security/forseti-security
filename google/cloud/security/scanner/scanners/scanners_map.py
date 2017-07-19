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

"""Map for mapping rules engine to scanner class"""

RESOURCE_MAP = {
    'bigquery_acl_violations': 'violations',
    'buckets_acl_violations': 'violations',
    'cloudsql_acl_violations': 'violations',
    'forwarding_rule_violations' : 'violations',
    'groups_violations': 'groups_violations',
    'instance_network_interface_violations': 'violations',
    'policy_violations': 'violations'
    'iap_violations': 'violations',
}
