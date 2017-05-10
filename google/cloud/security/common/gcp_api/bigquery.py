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

"""Wrapper for the BigQuery API client."""

import gflags as flags
from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

FLAGS = flags.FLAGS

flags.DEFINE_integer('max_bigquery_api_calls_per_100_seconds', 17000,
                     'BigQuery Discovery requests per 100 seconds.')

LOGGER = log_util.get_logger(__name__)

def extract_datasets(dataset_list_objects, key='datasets'):
    """Return a list of just dataset objects.

    Args: A list of dataset objects:
        [{
         "kind": "bigquery#datasetList",
         "etag": 'etag',
         "datasets": [
          {
           "kind": "bigquery#dataset",
           "id": "bq-test:test",
           "datasetReference": {
            "datasetId": "test",
            "projectId": "bq-test"
           }
          }
         ]
        },
        {
         "kind": "bigquery#datasetList",
         "etag": 'etag',
         "datasets": [
          {
           "kind": "bigquery#dataset",
           "id": "bq-test2:test2",
           "datasetReference": {
            "datasetId": "test2",
            "projectId": "bq-test2"
           }
          }
         ]
        }]

    Returns:
        A list of dataset objects like:
        [{'friendlyName': 'A String',
          'kind': 'bigquery#dataset',
          'labels': {'a_key': 'A String',},
          'id': 'A String',
          'datasetReference': {
               'projectId': 'A String',
               'datasetId': 'A String',
          },
          {'friendlyName': 'A String',
           'kind': 'bigquery#dataset',
           'labels': {'a_key': 'A String',},
           'id': 'A String',
           'datasetReference': {
               'projectId': 'A String',
               'datasetId': 'A String',
          },
        ]
    """
    return [item.get(key, []) for item in dataset_list_objects]



def extract_dataset_access(datasets, key='access'):
    """Return a list of just dataset access objects.

    Args: A list of datset_objects in the form of:
        [{
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
          }]

    Returns:
        [
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
    """
    return [ref.get(key, []) for _ in datasets for ref in datasets]

def extract_dataset_references(datasets, key='datasetReference'):
    """Return a list of just datasetReference objects.

    Args: A list of dataset list objects:
       [[{'datasetReference': {'datasetId': 'test', 'projectId': 'bq-test'},
       'id': 'bq-test:test',
       'kind': 'bigquery#dataset'}],
       [{'datasetReference': {'datasetId': 'test2', 'projectId': 'bq-test2'},
       'id': 'bq-test2:test2',
       'kind': 'bigquery#dataset'}]]

    Returns:
        A list of objects like:
        [{'projectId': 'bq-test',
          'datasetId': 'test'
          }, {
          'projectId': 'bq-test2',
          'datasetId': 'test2'
          }
        ]
    """
    return [ref.get(key, []) for _ in datasets for ref in datasets]


class BigQueryClient(_base_client.BaseClient):
    """BigQuery Client manager."""

    API_NAME = 'bigquery'

    # TODO: Remove pylint disable.
    # pylint: disable=invalid-name
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100
    # pylint: enable=invalid-name

    def __init__(self):
        super(BigQueryClient, self).__init__(
            api_name=self.API_NAME)
        self.rate_limiter = self.get_rate_limiter()

    def get_rate_limiter(self):
        """Return an appropriate rate limiter."""
        return RateLimiter(FLAGS.max_bigquery_api_calls_per_100_seconds,
                           self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def get_datasets_for_projectid(self, project_id):
        """Return BigQuery datasets stored in the requested project_id.

        Args:
            project_id: A String representing the unique project_id.

        Returns: A list of datasetReference objects for a given project_id.
            See extract_dataset_reference for details.
        """
        bigquery_stub = self.service.datasets()
        request = bigquery_stub.list(projectId=project_id, all=True)

        try:
            results = self._build_paged_result(
                request, bigquery_stub, self.rate_limiter)
        except (HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(self.API_NAME, e)

        datasets = extract_datasets(results)

        return extract_dataset_references(datasets)

    def get_dataset_access(self, project_id, dataset_id):
        """Return the access portion of the dataset resource object.

        Args:
            project_id: String representing the project id.
            dataset_id: String representing the dataset id.

        Returns: See extract_dataset_access()
        """
        bigquery_stub = self.service.datasets()
        request = bigquery_stub.get(projectId=project_id, datasetId=dataset_id)

        try:
            results = self._build_paged_result(
                request, bigquery_stub, self.rate_limiter)
        except (HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(self.API_NAME, e)

        return extract_dataset_access(results)
