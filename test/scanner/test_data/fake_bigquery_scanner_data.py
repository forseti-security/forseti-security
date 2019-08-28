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
"""BigQuery data to be used in the unit tests."""

from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.scanner.audit.bigquery_rules_engine import Rule


BIGQUERY_DATA = [{
    'project_id': 'p1',
    'dataset_id': 'd1',
    'full_name': 'organization/234/project/p1/dataset/d1/dataset_policy/d1/',
    'access_user_by_email': 'user@mockedexample.com',
    'role': 'OWNER',
    'view': '',
    'resource_data': 'inventory_dataset222',
}, {
    'project_id': 'p2',
    'dataset_id': 'd2',
    'full_name':  ('organization/234/folder/56/project/p2/dataset/d2/'
                   'dataset_policy/d2/'),
    'access_user_by_email': 'user1@mockedexample.com',
    'role': 'OWNER',
    'view': '',
    'resource_data': 'inventory_dataset333',
}]

BIGQUERY_EXPECTED_VIOLATION_LIST = [
    Rule.RuleViolation(
        domain='',
        resource_name='d1',
        resource_id='d1',
        full_name='organization/234/project/p1/dataset/d1/dataset_policy/d1/',
        special_group='',
        group_email='',
        rule_name='BigQuery test rule',
        role='OWNER',
        user_email='user@mockedexample.com',
        rule_index=0,
        dataset_id='d1',
        violation_type='BIGQUERY_VIOLATION',
        resource_type=resource_mod.ResourceType.DATASET,
        view={},
        resource_data='inventory_dataset222'),
    Rule.RuleViolation(
        domain='',
        resource_name='d2',
        resource_id='d2',
        full_name=('organization/234/folder/56/project/p2/dataset/d2/'
                   'dataset_policy/d2/'),
        special_group='',
        group_email='',
        rule_name='BigQuery test rule',
        role='OWNER',
        user_email='user1@mockedexample.com',
        rule_index=0,
        dataset_id='d2',
        violation_type='BIGQUERY_VIOLATION',
        resource_type=resource_mod.ResourceType.DATASET,
        view={},
        resource_data='inventory_dataset333')
]
