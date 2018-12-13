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

"""Wrapper for the BigQuery API client."""
from httplib2 import HttpLib2Error
from googleapiclient import errors

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'bigquery'


class BigQueryRepositoryClient(_base_repository.BaseRepositoryClient):
    """Big Query API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to false to disable the use of a rate
                limiter for this service.
        """
        if not quota_max_calls:
            use_rate_limiter = False

        self._projects = None
        self._datasets = None

        super(BigQueryRepositoryClient, self).__init__(
            API_NAME, versions=['v2'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def projects(self):
        """Returns a _BigQueryProjectsRepository instance."""
        if not self._projects:
            self._projects = self._init_repository(
                _BigQueryProjectsRepository)
        return self._projects

    @property
    def datasets(self):
        """Returns a _BigQueryDatasetsRepository instance."""
        if not self._datasets:
            self._datasets = self._init_repository(
                _BigQueryDatasetsRepository)
        return self._datasets
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _BigQueryProjectsRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Big Query Projects repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_BigQueryProjectsRepository, self).__init__(
            key_field=None, component='projects', **kwargs)


class _BigQueryDatasetsRepository(
        repository_mixins.GetQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Big Query Datasets repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_BigQueryDatasetsRepository, self).__init__(
            key_field='projectId', entity_field='datasetId',
            component='datasets', **kwargs)


class BigQueryClient(object):
    """BigQuery Client manager."""

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        self.repository = BigQueryRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_bigquery_projectids(self):
        """Request and page through bigquery projectids.

        Returns:
            list: A list of project_ids enabled for bigquery.

            If there are no project_ids enabled for bigquery an empty list will
            be returned.

        An example return value:

            ['project-id',
             'project-id',
             '...']
        """
        try:
            results = self.repository.projects.list(
                fields='nextPageToken,projects/id')
            flattened_results = api_helpers.flatten_list_results(
                results, 'projects')
            LOGGER.debug('Request and page through bigquery '
                         ' projectids, flattened_results = %s',
                         flattened_results)
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError('bigquery', e)

        project_ids = [result.get('id') for result in flattened_results
                       if 'id' in result]
        return project_ids

    def get_datasets_for_projectid(self, project_id):
        """Return BigQuery datasets stored in the requested project_id.

        Args:
            project_id (str): String representing the project id.

        Returns:
            list: A list of datasetReference objects for a given project_id

        An example return value:

            [{'datasetId': 'dataset-id',
              'projectId': 'project-id'},
             {...}]
        """
        try:
            results = self.repository.datasets.list(
                resource=project_id, all=True)
            flattened_results = api_helpers.flatten_list_results(
                results, 'datasets')
            LOGGER.debug('Getting bigquery datasets for a given project,'
                         ' project_id = %s, flattened_results = %s',
                         project_id, flattened_results)
            return flattened_results
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(project_id, e)

    def get_dataset_access(self, project_id, dataset_id):
        """Return the access portion of the dataset resource object.

        Args:
            project_id (str): String representing the project id.
            dataset_id (str): String representing the dataset id.

        Returns:
            list: A list of access lists for a given project_id and dataset_id.

        An example return value:

            [
                {'role': 'WRITER', 'specialGroup': 'projectWriters'},
                {'role': 'OWNER', 'specialGroup': 'projectOwners'},
                {'role': 'OWNER', 'userByEmail': 'user@domain.com'},
                {'role': 'READER', 'specialGroup': 'projectReaders'}
            ]
        """
        try:
            results = self.repository.datasets.get(resource=project_id,
                                                   target=dataset_id,
                                                   fields='access')
            access = results.get('access', [])
            LOGGER.debug('Geting the access portion of the dataset'
                         ' resource object, project_id = %s, dataset_id = %s,'
                         ' results = %s', project_id, dataset_id, access)
            return access
        except (errors.HttpError, HttpLib2Error) as e:
            raise api_errors.ApiExecutionError(project_id, e)
