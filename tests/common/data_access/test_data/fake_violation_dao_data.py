# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test data for violation dao tests."""

ROWS_MAP_BY_RESOURCE_1 = [
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_1',
     'rule_name': 'fake rule 1',
     'rule_index': 0,
     'violation_type': 'ADDED',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_2',
     'rule_name': 'fake rule 2',
     'rule_index': 0,
     'violation_type': 'REMOVED',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_3',
     'rule_name': 'fake rule 3',
     'rule_index': 0,
     'violation_type': 'BIGQUERY_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_4',
     'rule_name': 'fake rule 4',
     'rule_index': 0,
     'violation_type': 'BUCKET_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_5',
     'rule_name': 'fake rule 5',
     'rule_index': 0,
     'violation_type': 'CLOUD_SQL_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_6',
     'rule_name': 'fake rule 6',
     'rule_index': 0,
     'violation_type': 'FORWARDING_RULE_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_7',
     'rule_name': 'fake rule 7',
     'rule_index': 0,
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_8',
     'rule_name': 'fake rule 8',
     'rule_index': 0,
     'violation_type': 'FIREWALL_MATCHES_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_9',
     'rule_name': 'fake rule 9',
     'rule_index': 0,
     'violation_type': 'FIREWALL_REQUIRED_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_10',
     'rule_name': 'fake rule 10',
     'rule_index': 0,
     'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_11',
     'rule_name': 'fake rule 11',
     'rule_index': 0,
     'violation_type': 'GROUP_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_12',
     'rule_name': 'fake rule 12',
     'rule_index': 0,
     'violation_type': 'IAP_VIOLATION',
     'violation_data': '{}'},
    {'resource_type': 'fake_type',
     'resource_id': 'fake_id_13',
     'rule_name': 'fake rule 13',
     'rule_index': 0,
     'violation_type': 'INSTANCE_NETWORK_INTERFACE_VIOLATION',
     'violation_data': '{}'},
]

EXPECTED_MAP_BY_RESOURCE_1 = {
    'policy_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_1',
         'rule_name': 'fake rule 1',
         'rule_index': 0,
         'violation_type': 'ADDED',
         'violation_data': {}},
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_2',
         'rule_name': 'fake rule 2',
         'rule_index': 0,
         'violation_type': 'REMOVED',
         'violation_data': {}},
    ],
    'bigquery_acl_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_3',
         'rule_name': 'fake rule 3',
         'rule_index': 0,
         'violation_type': 'BIGQUERY_VIOLATION',
         'violation_data': {}},
    ],
    'buckets_acl_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_4',
         'rule_name': 'fake rule 4',
         'rule_index': 0,
         'violation_type': 'BUCKET_VIOLATION',
         'violation_data': {}},
    ],
    'cloudsql_acl_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_5',
         'rule_name': 'fake rule 5',
         'rule_index': 0,
         'violation_type': 'CLOUD_SQL_VIOLATION',
         'violation_data': {}},
    ],
    'forwarding_rule_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_6',
         'rule_name': 'fake rule 6',
         'rule_index': 0,
         'violation_type': 'FORWARDING_RULE_VIOLATION',
         'violation_data': {}},
    ],
    'firewall_rule_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_7',
         'rule_name': 'fake rule 7',
         'rule_index': 0,
         'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
         'violation_data': {}},
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_8',
         'rule_name': 'fake rule 8',
         'rule_index': 0,
         'violation_type': 'FIREWALL_MATCHES_VIOLATION',
         'violation_data': {}},
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_9',
         'rule_name': 'fake rule 9',
         'rule_index': 0,
         'violation_type': 'FIREWALL_REQUIRED_VIOLATION',
         'violation_data': {}},
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_10',
         'rule_name': 'fake rule 10',
         'rule_index': 0,
         'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
         'violation_data': {}},
    ],
    'groups_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_11',
         'rule_name': 'fake rule 11',
         'rule_index': 0,
         'violation_type': 'GROUP_VIOLATION',
         'violation_data': {}},
    ],
    'iap_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_12',
         'rule_name': 'fake rule 12',
         'rule_index': 0,
         'violation_type': 'IAP_VIOLATION',
         'violation_data': {}},
    ],
    'instance_network_interface_violations': [
        {'resource_type': 'fake_type',
         'resource_id': 'fake_id_13',
         'rule_name': 'fake rule 13',
         'rule_index': 0,
         'violation_type': 'INSTANCE_NETWORK_INTERFACE_VIOLATION',
         'violation_data': {}},
    ],
}
