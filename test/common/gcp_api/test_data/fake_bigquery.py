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

"""Test data for bigquery GCP api responses."""

PROJECT_IDS = ['bq-test','bq-test2']

DATASET_ID = 'test'

DATASETS_GET_REQUEST_RESPONSE = """
{
 "access": [
  {"role": "WRITER", "specialGroup": "projectWriters"},
  {"role": "OWNER", "specialGroup": "projectOwners"},
  {"role": "OWNER", "userByEmail": "user@domain.com"},
  {"role": "READER", "specialGroup": "projectReaders"}
 ],
 "creationTime": "1",
 "datasetReference": {
  "datasetId": "test",
  "projectId": "bq-test"
 },
 "etag": "T",
 "id": "bq-test:test",
 "kind": "bigquery#dataset",
 "lastModifiedTime": "1",
 "location": "US",
 "selfLink": ""
}
"""

DATASETS_GET_EXPECTED = [
    {'role': 'WRITER', 'specialGroup': 'projectWriters'},
    {'role': 'OWNER', 'specialGroup': 'projectOwners'},
    {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
    {'role': 'READER', 'specialGroup': 'projectReaders'}
]

PROJECTS_LIST_REQUEST_RESPONSE_EMPTY = [
    {'etag': '"T"',
     'kind': 'bigquery#projectList',
     'nextPageToken': '50',
     'projects': [],
     'totalItems': 2},
    {'etag': '"T2"',
     'kind': 'bigquery#projectList',
     'projects': [],
     'totalItems': 2}
]

PROJECTS_LIST_REQUEST_RESPONSE = [
    {'etag': '"T"',
     'kind': 'bigquery#projectList',
     'nextPageToken': '50',
     'projects': [{
         'friendlyName': '',
         'id': 'bq-test',
         'kind': 'bigquery#project',
         'numericId': '7',
         'projectReference': {'projectId': 'bq-test'}},
         ],
     'totalItems': 2},
    {'etag': '"T"',
     'kind': 'bigquery#projectList',
     'projects': [{
         'friendlyName': 'my_special_bq_test',
         'id': 'bq-test2',
         'kind': 'bigquery#project',
         'numericId': '5',
         'projectReference': {'projectId': 'bq-test2'}},
         ],
    'totalItems': 2}
]

PROJECTS_LIST_EXPECTED = PROJECT_IDS

DATASETS_LIST_REQUEST_RESPONSE = """
{
 "datasets": [{
  "datasetReference": {
   "datasetId": "test",
   "projectId": "bq-test"
  },
  "id": "bq-test:test",
  "kind": "bigquery#dataset"
 }],
 "etag": "T",
 "kind": "bigquery#datasetList"
}
"""

DATASETS_LIST_EXPECTED = [{
    'datasetReference': {
        'datasetId': 'test',
        'projectId': 'bq-test'
    },
    'id': 'bq-test:test',
    'kind': 'bigquery#dataset'
}]

PERMISSION_DENIED = """
{
 "error": {
  "code": 403,
  "message": "The caller does not have permission",
  "status": "PERMISSION_DENIED"
 }
}
"""

GET_TABLES_PAGE_1 = """
{
  "kind": "bigquery#tableList",
  "etag": "6M3sY2P57RlRag1RA5x-vVNSeSo/fuVUqg2afF6rsRcMDFKYmWpN06o",
  "tables": [
  {
    "kind": "bigquery#table",
    "id": "bqtable-test-project:bqtable_tb01s",
    "tableReference": {
    "projectId": "bqtable-test-project",
    "datasetId": "venus_data",
    "tableId": "venu01s"
    },
    "type": "TABLE",
    "creationTime": "1541099822329",
    "expirationTime": "1592939822329"
  },
  {
    "kind": "bigquery#table",
    "id": "bqtable-test-project:bqtable_tb02s",
    "tableReference": {
    "projectId": "bqtable-test-project",
    "datasetId": "venus_data",
    "tableId": "venu02s"
    },
    "type": "TABLE",
    "creationTime": "1542901234400",
    "expirationTime": "1594741234400"
  }
  ],
  "totalItems": 2,
  "nextPageToken": "token1"
}
"""

GET_TABLES_PAGE_2 = """
{
  "kind": "bigquery#tableList",
  "etag": "6M3sY2P57RlRag1RA5x-vVNSeSo/fuVUqg2afF6rsRcMDFKYmWpN06o",
  "tables": [
  {
    "kind": "bigquery#table",
    "id": "bqtable-test-project:bqtable_tb03s",
    "tableReference": {
    "projectId": "bqtable-test-project",
    "datasetId": "venus_data",
    "tableId": "venu03s"
    },
    "type": "TABLE",
    "creationTime": "1541099822329",
    "expirationTime": "1592939822329"
  },
  {
    "kind": "bigquery#table",
    "id": "bqtable-test-project:bqtable_tb04s",
    "tableReference": {
    "projectId": "bqtable-test-project",
    "datasetId": "venus_data",
    "tableId": "venu04s"
    },
    "type": "TABLE",
    "creationTime": "1542901234400",
    "expirationTime": "1594741234400"
  }
  ],
  "totalItems": 2
}
"""

GET_TABLES_RESPONSES = [GET_TABLES_PAGE_1,
                        GET_TABLES_PAGE_2]

TABLES_GET_EXPECTED = [
    {'kind': 'bigquery#table',
     'creationTime': '1541099822329',
     'tableReference': {'projectId': 'bqtable-test-project',
                         'tableId': 'venu01s',
                         'datasetId': 'venus_data'},
     'expirationTime': '1592939822329',
     'type': 'TABLE',
     'id': 'bqtable-test-project:bqtable_tb01s'},
    {'kind': 'bigquery#table',
     'creationTime': '1542901234400',
     'tableReference': {'projectId': 'bqtable-test-project',
                         'tableId': 'venu02s',
                         'datasetId': 'venus_data'},
     'expirationTime': '1594741234400',
     'type': 'TABLE',
     'id': 'bqtable-test-project:bqtable_tb02s'},
    {'kind': 'bigquery#table',
     'creationTime': '1541099822329',
     'tableReference': {'projectId': 'bqtable-test-project',
                         'tableId': 'venu03s',
                         'datasetId': 'venus_data'},
     'expirationTime': '1592939822329',
     'type': 'TABLE',
     'id': 'bqtable-test-project:bqtable_tb03s'},
    {'kind': 'bigquery#table',
     'creationTime': '1542901234400',
     'tableReference': {'projectId': 'bqtable-test-project',
                         'tableId': 'venu04s',
                         'datasetId': 'venus_data'},
     'expirationTime': '1594741234400',
     'type': 'TABLE',
     'id': 'bqtable-test-project:bqtable_tb04s'},
]
