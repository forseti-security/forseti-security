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

"""Wrapper for Cloud Billing API client."""
from googleapiclient import errors
from httplib2 import HttpLib2Error

from google.cloud.forseti.common.gcp_api import _base_repository
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class CloudBillingRepositoryClient(_base_repository.BaseRepositoryClient):
    """Cloud Billing API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=60.0,
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

        super(CloudBillingRepositoryClient, self).__init__(
            'cloudbilling', versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    # Turn off docstrings for properties.
    # pylint: disable=missing-return-doc, missing-return-type-doc
    @property
    def projects(self):
        """Returns a _CloudBillingProjectsRepository instance."""
        if not self._projects:
            self._projects = self._init_repository(
                _CloudBillingProjectsRepository)
        return self._projects
    # pylint: enable=missing-return-doc, missing-return-type-doc


class _CloudBillingProjectsRepository(_base_repository.GCPRepository):
    """Implementation of Cloud Billing Projects repository."""

    def __init__(self, **kwargs):
        """Constructor.

        Args:
            **kwargs (dict): The args to pass into GCPRepository.__init__()
        """
        super(_CloudBillingProjectsRepository, self).__init__(
            component='projects', **kwargs)

    def get_billing_info(self, name, fields=None):
        """Gets the billing information for a project.

        Args:
            name (str): The project name to query in the format
                projects/{project_id}.
            fields (str): Fields to include in the response - partial response.

        Returns:
            dict: The response from the API.
        """
        arguments = {'name': name,
                     'fields': fields}
        return self.execute_query(
            verb='getBillingInfo',
            verb_arguments=arguments,
        )

    @staticmethod
    def get_name(project_id):
        """Format's an organization_id to pass in to .get().

        Args:
            project_id (str): The project id to query, either just the
                id or the id prefixed with 'projects/'.

        Returns:
            str: The formatted resource name.
        """
        if not project_id.startswith('projects/'):
            project_id = 'projects/{}'.format(project_id)
        return project_id


class CloudBillingClient(object):
    """CloudSQL Client."""

    DEFAULT_QUOTA_PERIOD = 60.0

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get(
            'max_cloudbilling_api_calls_per_60_seconds')
        self.repository = CloudBillingRepositoryClient(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_PERIOD,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_billing_info(self, project_id):
        """Gets the biling information for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            dict: A ProjectBillingInfo resource.
            https://cloud.google.com/billing/reference/rest/v1/ProjectBillingInfo

            {
              "name": string,
              "projectId": string,
              "billingAccountName": string,
              "billingEnabled": boolean,
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP API fails.
        """

        try:
            name = self.repository.projects.get_name(project_id)
            return self.repository.projects.get_billing_info(name)
        except (errors.HttpError, HttpLib2Error) as e:
            if isinstance(e, errors.HttpError) and e.resp.status == 404:
                return {}
            LOGGER.warn(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError('billing_info', e)
