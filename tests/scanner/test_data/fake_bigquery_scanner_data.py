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

from google.cloud.security.scanner.audit.bigquery_rules_engine import Rule


BIGQUERY_DATA = [
    {
	'project_id': '12345678',
	'dataset_id': 'xza',
	'access_domain': '',
	'access_user_by_email': 'user@mockedexample.com',
	'access_group_by_email': '',
	'access_special_group': '',
	'role': 'OWNER'
	},
	{
	'project_id': '12345678',
	'dataset_id': 'xza',
	'access_domain': '',
	'access_user_by_email': 'user1@mockedexample.com',
	'access_group_by_email': '',
	'access_special_group': '',
	'role': 'OWNER'
	}
]

BIGQUERY_EXPECTED_VIOLATION_LIST = [Rule.RuleViolation(domain='', resource_id='xza', special_group='', group_email='', rule_name='BigQuery test rule', role='OWNER', user_email='user@mockedexample.com', rule_index=0, dataset_id='xza', violation_type='BIGQUERY_VIOLATION', resource_type='bigquery_dataset'), Rule.RuleViolation(domain='', resource_id='xza', special_group='', group_email='', rule_name='BigQuery test rule', role='OWNER', user_email='user1@mockedexample.com', rule_index=0, dataset_id='xza', violation_type='BIGQUERY_VIOLATION', resource_type='bigquery_dataset')]