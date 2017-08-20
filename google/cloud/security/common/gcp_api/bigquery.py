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
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class BigQueryRepository(_base_repository.BaseRepositoryClient):
    """Big Query API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
          quota_max_calls (int): Allowed requests per <quota_period> for the
              API.
          quota_period (float): The time period to limit the quota_requests to.
          use_rate_limiter (bool): Set to false to disable the use of a rate
              limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._projects = None
        self._datasets = None

        super(BigQueryRepository, self).__init__(
            'bigquery', versions=['v2'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    @property
    def projects(self):
        """A _BigQueryProjectsRepository instance.

        Returns:
          object: A _BigQueryProjectsRepository instance.
        """
        if not self._projects:
            self._projects = self._init_repository(
                _BigQueryProjectsRepository,
                self.gcp_services['v2'],
                self._projects)

        return self._projects

    @property
    def datasets(self):
        """A _BigQueryDatasetsRepository instance.

        Returns:
          object: A _BigQueryDatasetsRepository instance.
        """
        if not self._datasets:
            self._datasets = self._init_repository(
                _BigQueryDatasetsRepository,
                self.gcp_services['v2'],
                self._datasets)

        return self._datasets


class _BigQueryProjectsRepository(
        _base_repository.GCPRepository,
        _base_repository.ListQueryMixin):
    """Implementation of Big Query Projects repository."""

    def __init__(self, gcp_service, credentials, rate_limiter):
        """Constructor.

        Args:
          gcp_service (object): A GCE service object built using the Google
              discovery API.
          credentials (object): GoogleCredentials.
          rate_limiter (object): A rate limiter instance.
        """
        super(_BigQueryProjectsRepository, self).__init__(
            gcp_service=gcp_service,
            credentials=credentials,
            key_field='',
            component='projects',
            entity='',
            rate_limiter=rate_limiter)


class _BigQueryDatasetsRepository(
        _base_repository.GCPRepository,
        _base_repository.GetQueryMixin,
        _base_repository.ListQueryMixin):
    """Implementation of Big Query Datasets repository."""

    def __init__(self, gcp_service, credentials, rate_limiter):
        """Constructor.

        Args:
          gcp_service (object): A GCE service object built using the Google
              discovery API.
          credentials (object): GoogleCredentials.
          rate_limiter (object): A rate limiter instance.
        """
        super(_BigQueryDatasetsRepository, self).__init__(
            gcp_service=gcp_service,
            credentials=credentials,
            key_field='projectId',
            component='datasets',
            entity='datasetId',
            rate_limiter=rate_limiter)


class BigQueryClient(object):
    """BigQuery Client manager."""

    # TODO: Remove pylint disable.
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100.0  # pylint: disable=invalid-name

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_bigquery_api_calls_per_100_seconds')
        self.repository = BigQueryRepository(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_bigquery_projectids(self):
        """Request and page through bigquery projectids.

        Returns:
            list: A list of project_ids enabled for bigquery.

            ['project-id',
             'project-id',
             '...']

            If there are no project_ids enabled for bigquery an empty list will
            be returned.
        """
        try:
            results = self.repository.projects.list(
                fields='nextPageToken,projects/id')
            flattened = _base_repository.flatten_list_results(results,
                                                              'projects')
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('bigquery', e)

        project_ids = [result.get('id') for result in flattened
                       if 'id' in result]

        return project_ids

    def get_datasets_for_projectid(self, project_id):
        """Return BigQuery datasets stored in the requested project_id.

        Args:
            project_id (str): String representing the project id.

        Returns:
            list: A list of datasetReference objects for a given project_id.

            [{'datasetId': 'dataset-id',
              'projectId': 'project-id'},
             {...}]
        """
        try:
            results = self.repository.datasets.list(
                resource=project_id,
                fields='datasets/datasetReference,nextPageToken',
                all=True)
            flattened = _base_repository.flatten_list_results(results,
                                                              'datasets')
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(project_id, e)

        datasets = [result.get('datasetReference') for result in flattened
                    if 'datasetReference' in result]

        return datasets

    def get_dataset_access(self, project_id, dataset_id):
        """Return the access portion of the dataset resource object.

        Args:
            project_id (str): String representing the project id.
            dataset_id (str): String representing the dataset id.

        Returns:
            list: A list of access lists for a given project_id and dataset_id.
            [{'role': 'WRITER', 'specialGroup': 'projectWriters'},
             {'role': 'OWNER', 'specialGroup': 'projectOwners'},
             {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
             {'role': 'READER', 'specialGroup': 'projectReaders'}]
        """
        try:
            results = self.repository.datasets.get(resource=project_id,
                                                   target=dataset_id,
                                                   fields='access')
            return results.get('access', [])
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(project_id, e)
