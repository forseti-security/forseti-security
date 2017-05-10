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


FAKE_BIGQUERY_DATASETID = ['d1', 'd2', 'd3']

FAKE_BIGQUERY_PROJECTID = 'p1'

FAKE_BIGQUERY_DATASET_PROJECT_MAP = [
    {'projectId': FAKE_BIGQUERY_PROJECTID,
     'datasetId': FAKE_BIGQUERY_DATASETID[0]},
    {'projectId': FAKE_BIGQUERY_PROJECTID,
     'datasetId': FAKE_BIGQUERY_DATASETID[1]},
    {'projectId': FAKE_BIGQUERY_PROJECTID,
     'datasetId': FAKE_BIGQUERY_DATASETID[2]}
]

FAKE_DATASET_ACCESS = [
    {'role': 'A String',
     'userByEmail': 'A String',
     'groupByEmail': 'A String',
     'domain': 'A String',
     'specialGroup': 'A String',
     'view': {'projectId': FAKE_BIGQUERY_PROJECTID,
              'datasetId': FAKE_BIGQUERY_DATASETID[0],
              'tableId': 'A String'}
    },
    {'role': 'A String',
     'userByEmail': 'A String',
     'groupByEmail': 'A String',
     'domain': 'A String',
     'specialGroup': 'A String',
     'view': {'projectId': FAKE_BIGQUERY_PROJECTID,
              'datasetId': FAKE_BIGQUERY_DATASETID[1],
              'tableId': 'A String'}
    },
    {'role': 'A String',
     'userByEmail': 'A String',
     'groupByEmail': 'A String',
     'domain': 'A String',
     'specialGroup': 'A String',
     'view': {'projectId': FAKE_BIGQUERY_PROJECTID,
              'datasetId': FAKE_BIGQUERY_DATASETID[2],
              'tableId': 'A String'}
    }
]

FAKE_DATASET_PROJECT_ACCESS_MAP = [
    (FAKE_BIGQUERY_PROJECTID,
     FAKE_BIGQUERY_DATASETID[0],
     FAKE_DATASET_ACCESS),
    (FAKE_BIGQUERY_PROJECTID,
     FAKE_BIGQUERY_DATASETID[1],
     FAKE_DATASET_ACCESS),
    (FAKE_BIGQUERY_PROJECTID,
     FAKE_BIGQUERY_DATASETID[2],
     FAKE_DATASET_ACCESS)
]

FAKE_EXPECTED_LOADABLE_DATASETS = [
    {'access_domain': 'A String',
     'access_group_by_email': 'A String',
     'access_special_group': 'A String',
     'access_user_by_email': 'A String',
     'access_view_dataset_id': 'd1',
     'access_view_project_id': 'p1',
     'access_view_table_id': 'A String',
     'datset_id': 'd1',
     'project_id': 'p1',
     'raw_access_map': {'domain': 'A String',
                        'groupByEmail': 'A String',
                        'role': 'A String',
                        'specialGroup': 'A String',
                        'userByEmail': 'A String',
                        'view': {'datasetId': 'd1',
                                 'projectId': 'p1',
                                 'tableId': 'A String'}},
     'role': 'A String'
    }, {
     'access_domain': 'A String',
     'access_group_by_email': 'A String',
     'access_special_group': 'A String',
     'access_user_by_email': 'A String',
     'access_view_dataset_id': 'd2',
     'access_view_project_id': 'p1',
     'access_view_table_id': 'A String',
     'datset_id': 'd1',
     'project_id': 'p1',
     'raw_access_map': {'domain': 'A String',
                        'groupByEmail': 'A String',
                        'role': 'A String',
                        'specialGroup': 'A String',
                        'userByEmail': 'A String',
                        'view': {'datasetId': 'd2',
                                 'projectId': 'p1',
                                 'tableId': 'A String'}},
     'role': 'A String'
  }, {
     'access_domain': 'A String',
     'access_group_by_email': 'A String',
     'access_special_group': 'A String',
     'access_user_by_email': 'A String',
     'access_view_dataset_id': 'd3',
     'access_view_project_id': 'p1',
     'access_view_table_id': 'A String',
     'datset_id': 'd1',
     'project_id': 'p1',
     'raw_access_map': {'domain': 'A String',
                        'groupByEmail': 'A String',
                        'role': 'A String',
                        'specialGroup': 'A String',
                        'userByEmail': 'A String',
                        'view': {'datasetId': 'd3',
                                 'projectId': 'p1',
                                 'tableId': 'A String'}},
     'role': 'A String'
    }, {
     'access_domain': 'A String',
     'access_group_by_email': 'A String',
     'access_special_group': 'A String',
     'access_user_by_email': 'A String',
     'access_view_dataset_id': 'd1',
     'access_view_project_id': 'p1',
     'access_view_table_id': 'A String',
     'datset_id': 'd2',
     'project_id': 'p1',
     'raw_access_map': {'domain': 'A String',
                        'groupByEmail': 'A String',
                        'role': 'A String',
                        'specialGroup': 'A String',
                        'userByEmail': 'A String',
                        'view': {'datasetId': 'd1',
                                 'projectId': 'p1',
                                 'tableId': 'A String'}},
     'role': 'A String'
    }, {
     'access_domain': 'A String',
     'access_group_by_email': 'A String',
     'access_special_group': 'A String',
     'access_user_by_email': 'A String',
     'access_view_dataset_id': 'd2',
     'access_view_project_id': 'p1',
     'access_view_table_id': 'A String',
     'datset_id': 'd2',
     'project_id': 'p1',
     'raw_access_map': {'domain': 'A String',
                        'groupByEmail': 'A String',
                        'role': 'A String',
                        'specialGroup': 'A String',
                        'userByEmail': 'A String',
                        'view': {'datasetId': 'd2',
                                 'projectId': 'p1',
                                 'tableId': 'A String'}},
     'role': 'A String'
    }, {
     'access_domain': 'A String',
     'access_group_by_email': 'A String',
     'access_special_group': 'A String',
     'access_user_by_email': 'A String',
     'access_view_dataset_id': 'd3',
     'access_view_project_id': 'p1',
     'access_view_table_id': 'A String',
     'datset_id': 'd2',
     'project_id': 'p1',
     'raw_access_map': {'domain': 'A String',
                        'groupByEmail': 'A String',
                        'role': 'A String',
                        'specialGroup': 'A String',
                        'userByEmail': 'A String',
                        'view': {'datasetId': 'd3',
                                 'projectId': 'p1',
                                 'tableId': 'A String'}},
      'role': 'A String'
    }, {
      'access_domain': 'A String',
      'access_group_by_email': 'A String',
      'access_special_group': 'A String',
      'access_user_by_email': 'A String',
      'access_view_dataset_id': 'd1',
      'access_view_project_id': 'p1',
      'access_view_table_id': 'A String',
      'datset_id': 'd3',
      'project_id': 'p1',
      'raw_access_map': {'domain': 'A String',
                         'groupByEmail': 'A String',
                         'role': 'A String',
                         'specialGroup': 'A String',
                         'userByEmail': 'A String',
                         'view': {'datasetId': 'd1',
                                  'projectId': 'p1',
                                  'tableId': 'A String'}},
      'role': 'A String'
    },  {
      'access_domain': 'A String',
      'access_group_by_email': 'A String',
      'access_special_group': 'A String',
      'access_user_by_email': 'A String',
      'access_view_dataset_id': 'd2',
      'access_view_project_id': 'p1',
      'access_view_table_id': 'A String',
      'datset_id': 'd3',
      'project_id': 'p1',
      'raw_access_map': {'domain': 'A String',
                         'groupByEmail': 'A String',
                         'role': 'A String',
                         'specialGroup': 'A String',
                         'userByEmail': 'A String',
                         'view': {'datasetId': 'd2',
                                  'projectId': 'p1',
                                  'tableId': 'A String'}},
      'role': 'A String'
    },  {
      'access_domain': 'A String',
      'access_group_by_email': 'A String',
      'access_special_group': 'A String',
      'access_user_by_email': 'A String',
      'access_view_dataset_id': 'd3',
      'access_view_project_id': 'p1',
      'access_view_table_id': 'A String',
      'datset_id': 'd3',
      'project_id': 'p1',
      'raw_access_map': {'domain': 'A String',
                         'groupByEmail': 'A String',
                         'role': 'A String',
                         'specialGroup': 'A String',
                         'userByEmail': 'A String',
                         'view': {'datasetId': 'd3',
                                  'projectId': 'p1',
                                  'tableId': 'A String'}},
      'role': 'A String'
    }
]
