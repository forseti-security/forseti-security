# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Wrapper for Service Management API client."""
from builtins import object
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
API_NAME = 'serviceusage'


class ServiceUsageRepositoryClient(_base_repository.BaseRepositoryClient):
    """Service Usage API Repository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=100.0,
                 use_rate_limiter=True,
                 cache_discovery=False,
                 cache=None):
        """Constructor.

        Args:
            quota_max_calls (int): Allowed requests per <quota_period> for the
                API.
            quota_period (float): The time period to track requests over.
            use_rate_limiter (bool): Set to False to disable the use of a rate
                limiter for this service.
        """

        if not quota_max_calls:
            use_rate_limiter = False

        self._services = None

        super(ServiceUsageRepositoryClient, self).__init__(
            API_NAME, versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter,
            cache_discover=cache_discovery,
            cache=cache)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def services(self):
        """Returns a _ServiceUsageRepository instance."""

        if not self._services:
            self._services = self._init_repository(
                _ServiceUsageServicesRepository)

        return self._services


class _ServiceUsageServicesRepository(
        repository_mixins.GetIamPolicyQueryMixin,
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Service Usage Services repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """

        super(_ServiceUsageServicesRepository, self).__init__(
            component='services', max_results_field='pageSize', **kwargs)

    @staticmethod
    def get_formatted_project_name(project_id):
        """Returns a formatted project name string field to pass in to the API.

        Args:
            project_id (str): The id of the project to query.

        Returns:
            str: A formatted project name.
        """

        if not project_id.startswith('projects/'):
            project_id = 'projects/{}'.format(project_id)
        return project_id


class ServiceUsageClient(object):
    """Service Usage Client."""

    # Maximum number f results to fetch per page for paged API calls
    DEFAULT_MAX_RESULTS = 100

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """

        max_calls, quota_period = api_helpers.get_ratelimiter_config(
            global_configs, API_NAME)

        cache_discovery = global_configs[
            'cache_discovery'] if 'cache_discovery' in global_configs else False

        self.repository = ServiceUsageRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=quota_period,
            use_rate_limiter=kwargs.get('use_rate_limiter', True),
            cache_discovery=cache_discovery,
            cache=global_configs.get('cache'))

    def get_enabled_apis(self, project_id):
        """Gets the enabled APIs for a project.

        Args:
            project_id (str): The project id for a GCP project.

        Returns:
            list: A list of Services resource dicts.
            https://cloud.google.com/service-usage/docs/reference/rest/v1/services#Service

            {
              "name": string,
              "parent": string,
              "config": {
                object (ServiceConfig)
              },
              "state": enum (State)
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """

        formatted_project_name = (
            self.repository.services.get_formatted_project_name(project_id))

        enabled_filter = 'state:ENABLED'

        try:
            paged_results = self.repository.services.list(
                parent=formatted_project_name,
                max_results=self.DEFAULT_MAX_RESULTS,
                filter=enabled_filter)
            flattened_results = api_helpers.flatten_list_results(paged_results,
                                                                 'services')

        except (errors.HttpError, HttpLib2Error) as e:
            api_exception = api_errors.ApiExecutionError(
                'serviceusage_enabledapis', e, 'project_id', project_id)
            LOGGER.exception(api_exception)
            raise api_exception

        LOGGER.debug('Getting the enabled APIs for project_id = %s, '
                     'flattened_results = %s', project_id, flattened_results)

        return flattened_results
