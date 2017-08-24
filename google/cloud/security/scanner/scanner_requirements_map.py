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

"""Map of the requirements needed by the scanners."""

# TODO: Standardize the module and class names so that we can use reflection
# instead of maintaining them explicitly.
# Use the naming pattern foo_module.py, class FooModule
REQUIREMENTS_MAP = {
    'bigquery':
        {'module_name': 'bigquery_scanner',
         'class_name': 'BigqueryScanner',
         'rules_filename': 'bigquery_rules.yaml'},
    'bucket_acl':
        {'module_name': 'bucket_rules_scanner',
         'class_name': 'BucketsAclScanner',
         'rules_filename': 'bucket_rules.yaml'},
    'cloudsql_acl':
        {'module_name': 'cloudsql_rules_scanner',
         'class_name': 'CloudSqlAclScanner',
         'rules_filename': 'cloudsql_rules.yaml'},
    'forwarding_rule':
        {'module_name': 'forwarding_rule_scanner',
         'class_name': 'ForwardingRuleScanner',
         'rules_filename': 'forwarding_rules.yaml'},
    'group':
        {'module_name': 'groups_scanner',
         'class_name': 'GroupsScanner',
         'rules_filename': 'group_rules.yaml'},
    'iam_policy':
        {'module_name': 'iam_rules_scanner',
         'class_name': 'IamPolicyScanner',
         'rules_filename': 'iam_rules.yaml'},
    'iap':
        {'module_name': 'iap_scanner',
         'class_name': 'IapScanner',
         'rules_filename': 'iap_rules.yaml'},
    'instance_network_interface':
        {'module_name': 'instance_network_interface_scanner',
         'class_name': 'InstanceNetworkInterfaceScanner',
         'rules_filename': 'instance_network_interface_rules.yaml'},
}
