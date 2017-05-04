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


class BigQueryClient(_base_client.BaseClient):
    """BigQuery Client."""

    API_NAME = 'bigquery'
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100

    def __init__(self):
        super(BigQueryClient, self).__init__(
            api_name=self.API_NAME)
        self.rate_limiter = self.get_rate_limiter()

    def _extract_dataset_access(self, dataset_object):
        """Return a list of just dataset access objects.

        Args: A datset_object in the form of:
            https://developers.google.com/resources/api-libraries/documentation/bigquery/v2/python/latest/bigquery_v2.datasets.html#get

        Returns:
            "access": [{"domain": "A String", "userByEmail": "A String", "specialGroup": "A String", "groupByEmail": "A String", "role": "A String", "view": {"projectId": "A String", "tableId": "A String", "datasetId": "A String", }, },]
        """
        return [item.get('access', []) for item in dataset_objects]

    def _extract_datasets(self, dataset_list_objects):
        """Return a list of just dataset objects.

        Args: A dataset list object in the form of:
            {"kind": "bigquery#datasetList",
            "etag": etag,
            "nextPageToken": string,
            "datasets": [
               {
                  "kind": "bigquery#dataset",
                  "id": "string",
                  "datasetReference": {
                    "datasetId": "string",
                    "projectId": "string"
                  },
                  "labels": {
                    "key": "string"
                  },
                  "friendlyName": "string"
                },
                {
                  "kind": "bigquery#dataset",
                  "id": "string",
                  "datasetReference": {
                    "datasetId": "string",
                    "projectId": "string"
                  },
                  "labels": {
                    "key": "string"
                  },
                  "friendlyName": "string"
                }
            ]}

        Returns:
            A list of dataset objects like:
            [{'friendlyName': 'string',
              'kind': 'bigquery#dataset',
              'labels': {'key': 'string'},
              'id': 'string',
              'datasetReference': {'projectId': 'string',
                                   'datasetId': 'string'}
             },{...}
            ]
        """
        return [item.get('datasets', []) for item in dataset_list_objects]

    def _extract_dataset_references(self, dataset_objects):
        """Return a list of just datasetReference objects.

        Args:
            dataset_objects: A list of objects like:
            [{'friendlyName': 'string',
              'kind': 'bigquery#dataset',
              'labels': {'key': 'string'},
              'id': 'string',
              'datasetReference': {'projectId': 'string',
                                   'datasetId': 'string'}
             },{...}
            ]

        Returns:
            A list of objects like:
            [{'projectId': 'string', 'datasetId': 'string'},
             {'projectId': 'string', 'datasetId': 'string'},
             {'projectId': 'string', 'datasetId': 'string'}]
        """
        return [item.get('datasetsReference', []) for item in dataset_objects]

    def get_rate_limiter(self):
        """Return an appropriate rate limiter."""
        return RateLimiter(FLAGS.max_bigquery_api_calls_per_100_seconds,
                           self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def get_datasets_for_project_id(self, project_id):
        """Return BigQuery datasets stored in the requested project_id.

        Args:
            project_id: A String representing the unique project_id.

        Returns: A list of datasetReference objects for a given project_id.
            See _extract_dataset_reference for details.
        """
        bigquery_stub = self.service.datasets()

        request = bigquery_stub.list(projectId=project_id, all=True)
        results = self._build_paged_result(
            request, bigquery_stub, self.rate_limiter)

        datasets = self._extract_datasets(results)

        return self._extract_dataset_references(datasets)

    def get_dataset_access(self, project_id, dataset_id):
      """Return access portion of the dataset resource object.

      Args:
          project_id: String representing the project id.
          dataset_id: String representing the dataset id.

      Returns:
          A data set resource object as a dictionary.
          See https://cloud.google.com/bigquery/docs/reference/rest/v2/datasets#resource
      """
      bigquery_stub = self.service.datasets()

      request = bigquery_stub.get(projectId=project_id, datasetId=dataset_id)
      results = self._build_paged_result(
          request, bigquery_stub, self.rate_limiter)

      dataset_access = self._extract_dataset_access(results)

      return self._extract_dataset_references(datasets)
