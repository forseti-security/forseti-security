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
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.util import log_util

FLAGS = flags.FLAGS

flags.DEFINE_integer('max_bigquery_api_calls_per_100_seconds', 17000,
                     'BigQuery Discovery requests per 100 seconds.')

LOGGER = log_util.get_logger(__name__)

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

    def get_bigquery_projectids(self):
        """Request and page through bigquery projectids.

        Returns: A list of project_ids enabled for bigquery.

            ['project-id',
             'project-id',
             '...']

            If there are no project_ids enabled for bigquery an empty list will
            be returned.
        """
        bigquery_projects_api = self.service.projects()
        request = bigquery_projects_api.list()

        results = self._build_paged_result(request, bigquery_projects_api,
                                           self.rate_limiter)
        project_ids = []
        for result in results:
            for project in result.get('projects', []):
                project_ids.append(project.get('id'))

        return project_ids

    def get_datasets_for_projectid(self, project_id, key='datasets'):
        """Return BigQuery datasets stored in the requested project_id.

        Args:
            project_id: String representing the project id.

        Returns: A list of datasetReference objects for a given project_id.

            [{'datasetId': 'dataset-id',
              'projectId': 'project-id'},
             {...}]
        """
        bigquery_datasets_api = self.service.datasets()
        request = bigquery_datasets_api.list(projectId=project_id, all=True)

        results = self._build_paged_result(request, bigquery_datasets_api,
                                           self.rate_limiter)
        datasets = []
        for result in results:
            if key in result:
                for item in result.get(key):
                    datasets.append(item.get('datasetReference'))

        return datasets

    def get_dataset_access(self, project_id, dataset_id, key='access'):
        """Return the access portion of the dataset resource object.

        Args:
            project_id: String representing the project id.
            dataset_id: String representing the dataset id.

        Returns: A list of access lists for a given project_id and dataset_id.
           [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
            {'role': 'OWNER', 'specialGroup': 'projectOwners'},
            {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
            {'role': 'READER', 'specialGroup': 'projectReaders'}]
        """
        bigquery_datasets_api = self.service.datasets()
        request = bigquery_datasets_api.get(projectId=project_id,
                                            datasetId=dataset_id)

        results = self._build_paged_result(request, bigquery_datasets_api,
                                           self.rate_limiter)
        access_list = []
        for result in results:
            if key in result:
                for item in result.get(key):
                    access_list.append(item)

        return access_list
