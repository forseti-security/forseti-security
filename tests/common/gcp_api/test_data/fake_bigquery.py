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

"""Test data for bigquery GCP api responses."""

PROJECT_IDS = ['bq-test']

DATASET_ID = 'test'

DATASET_LISTS = [{
  "kind": "bigquery#datasetList",
  "etag": 'etag',
  "datasets": [{
      "kind": "bigquery#dataset",
      "id": "bq-test:test",
            "datasetReference": {
              "datasetId": "test",
              "projectId": "bq-test"}
      }]
   }, {
  "kind": "bigquery#datasetList",
  "etag": 'etag',
  "datasets": [{
      "kind": "bigquery#dataset",
      "id": "bq-test2:test2",
      "datasetReference": {
          "datasetId": "test2",
          "projectId": "bq-test2"
      }
  }]
}]

EXPECTED_DATASETS_LISTS = [
    [{
      'datasetReference': {
        'datasetId': 'test',
        'projectId': 'bq-test'
      },
      'id': 'bq-test:test',
      'kind': 'bigquery#dataset'
    }],
    [{
      'datasetReference': {
        'datasetId': 'test2',
        'projectId': 'bq-test2'
      },
      'id': 'bq-test2:test2',
      'kind': 'bigquery#dataset'
    }]
]

EXPECTED_DATASET_REFERENCES = [{
  'projectId': 'bq-test',
  'datasetId': 'test'
  }, {
  'projectId': 'bq-test2',
  'datasetId': 'test2'
  }
]

DATASETS = [{
    'kind': 'bigquery#dataset',
    'etag': 'etag',
    'id': 'bq-test:test',
    'selfLink': 'link',
    'datasetReference': {
        'datasetId': 'test',
        'projectId': 'bq-test'
    },
    'access': [
        {
            'role': 'WRITER',
            'specialGroup': 'projectWriters'
        },
        {
            'role': 'OWNER',
            'specialGroup': 'projectOwners'
        },
        {
            'role': 'OWNER',
            'userByEmail': 'm@m.com'
        },
        {
            'role': 'READER',
            'specialGroup': 'projectReaders'
        }
    ],
    'creationTime': '1',
    'lastModifiedTime': '2'
  }, {
  'kind': 'bigquery#dataset',
  'etag': 'etag',
  'id': 'bq-test2:test2',
  'selfLink': 'link',
  'datasetReference': {
    'datasetId': 'test2',
    'projectId': 'bq-test2'
  },
  'access': [
    {
      'role': 'WRITER',
      'specialGroup': 'projectWriters'
    },
    {
      'role': 'OWNER',
      'specialGroup': 'projectOwners'
    },
    {
      'role': 'OWNER',
      'userByEmail': 'm@m.com'
    },
    {
      'role': 'READER',
      'specialGroup': 'projectReaders'
    }
  ],
  'creationTime': '1',
  'lastModifiedTime': '2'
  }
]

EXPECTED_DATASET_ACCESS = [
    [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
        {'role': 'OWNER', 'specialGroup': 'projectOwners'},
        {'role': 'OWNER', 'userByEmail': 'm@m.com'},
        {'role': 'READER', 'specialGroup': 'projectReaders'}],
    [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
        {'role': 'OWNER', 'specialGroup': 'projectOwners'},
        {'role': 'OWNER', 'userByEmail': 'm@m.com'},
        {'role': 'READER', 'specialGroup': 'projectReaders'}],
    [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
        {'role': 'OWNER', 'specialGroup': 'projectOwners'},
        {'role': 'OWNER', 'userByEmail': 'm@m.com'},
        {'role': 'READER', 'specialGroup': 'projectReaders'}],
    [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
        {'role': 'OWNER', 'specialGroup': 'projectOwners'},
        {'role': 'OWNER', 'userByEmail': 'm@m.com'},
        {'role': 'READER', 'specialGroup': 'projectReaders'}]
]
