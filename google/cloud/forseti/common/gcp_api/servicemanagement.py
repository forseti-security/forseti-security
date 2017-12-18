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

"""Wrapper for Service Management API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import api_helpers
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ServiceManagementRepositoryClient(_base_repository.BaseRepositoryClient):
    """ServiceManagement API Respository."""

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

        self._services = None

        super(ServiceManagementRepositoryClient, self).__init__(
            'servicemanagement', versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def services(self):
        """Returns a _ServiceManagementServicesRepository instance."""
        if not self._services:
            self._services = self._init_repository(
                _ServiceManagementServicesRepository)
        return self._services
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _ServiceManagementServicesRepository(
        repository_mixins.ListQueryMixin,
        _base_repository.GCPRepository):
    """Implementation of Service Management Services repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_ServiceManagementServicesRepository, self).__init__(
            component='services', max_results_field='pageSize', key_field=None,
            **kwargs)

    @staticmethod
    def get_name(project_id):
        """Format's an organization_id to pass in to .get().

        Args:
            project_id (str): The project id to query, either just the
                id or the id prefixed with 'projects/'.

        Returns:
            str: The formatted resource name.
        """
        if not project_id.startswith('project:'):
            project_id = 'project:{}'.format(project_id)
        return project_id


class ServiceManagementClient(object):
    """Service Management Client."""

    DEFAULT_QUOTA_PERIOD = 100.0

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get(
            'max_servicemanagement_api_calls_per_100_seconds', 200)
        self.repository = ServiceManagementRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_PERIOD,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_enabled_apis(self, project_id):
        """Gets the enabled APIs for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            list: A list of ManagedService resource dicts.
            https://cloud.google.com/service-management/reference/rest/v1/services#ManagedService

            {
              "serviceName": string,
              "producerProjectId": string,
            }
        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """

        try:
            name = self.repository.services.get_name(project_id)
            paged_results = self.repository.services.list(consumerId=name,
                                                          max_results=100)
            return api_helpers.flatten_list_results(paged_results, 'services')
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.warn(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError(name, e)
