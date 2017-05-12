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

"""Pipeline to load bigquery datasets data into Inventory."""

import json

DATASET_PROJECT_MAP = [
    [{'datasetId': 'test', 'projectId': 'bq-test'}],
    [{'datasetId': 'test', 'projectId': 'bq-test'}]
]

DATASET_PROJECT_MAP_EXPECTED = DATASET_PROJECT_MAP

GET_DATASETS_FOR_PROJECTIDS_RETURN = [
    {'datasetId': 'test', 'projectId': 'bq-test'}
]

GET_DATASET_ACCESS_RETURN = [
    {'role': 'WRITER', 'specialGroup': 'projectWriters'},
    {'role': 'OWNER', 'specialGroup': 'projectOwners'},
    {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
    {'role': 'READER', 'specialGroup': 'projectReaders'}
]

RETRIEVE_DATASET_ACCESS_RETURN = GET_DATASET_ACCESS_RETURN

GET_DATASETS_LIST_RETURN = [
    {'datasetId': 'test', 'projectId': 'bq-test'},
    {'datasetId': 'test', 'projectId': 'bq-test'}
]

DATASET_PROJECT_ACCESS_MAP = [
    ('bq-test',
     'test',
     [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
      {'role': 'OWNER', 'specialGroup': 'projectOwners'},
      {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
      {'role': 'READER', 'specialGroup': 'projectReaders'}]),
    ('bq-test',
     'test',
     [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
      {'role': 'OWNER', 'specialGroup': 'projectOwners'},
      {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
      {'role': 'READER', 'specialGroup': 'projectReaders'}])
]

EXPECTED_TRANSFORM = [
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': 'projectWriters',
    'access_user_by_email': None,
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'WRITER',
                                  'specialGroup': 'projectWriters'}),
    'role': 'WRITER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': 'projectOwners',
    'access_user_by_email': None,
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'OWNER',
                                  'specialGroup': 'projectOwners'}),
    'role': 'OWNER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': None,
    'access_user_by_email': 'user@domain.com',
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'OWNER',
                                  'userByEmail': 'user@domain.com'}),
    'role': 'OWNER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': 'projectReaders',
    'access_user_by_email': None,
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'READER',
                                  'specialGroup': 'projectReaders'}),
    'role': 'READER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': 'projectWriters',
    'access_user_by_email': None,
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'WRITER',
                                  'specialGroup': 'projectWriters'}),
    'role': 'WRITER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': 'projectOwners',
    'access_user_by_email': None,
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'OWNER',
                                  'specialGroup': 'projectOwners'}),
    'role': 'OWNER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': None,
    'access_user_by_email': 'user@domain.com',
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'OWNER',
                                  'userByEmail': 'user@domain.com'}),
    'role': 'OWNER'},
    {'access_domain': None,
    'access_group_by_email': None,
    'access_special_group': 'projectReaders',
    'access_user_by_email': None,
    'access_view_dataset_id': None,
    'access_view_project_id': None,
    'access_view_table_id': None,
    'dataset_id': 'test',
    'project_id': 'bq-test',
    'raw_access_map': json.dumps({'role': 'READER',
                                  'specialGroup': 'projectReaders'}),
    'role': 'READER'}
]

DATASET_PROJECT_ACCESS_MAP_EXPECTED = DATASET_PROJECT_ACCESS_MAP