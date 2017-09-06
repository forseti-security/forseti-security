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

"""Wrapper for Storage API client."""


from googleapiclient import errors
from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.iam.inventory.gcp_api2 import _base_client
from google.cloud.security.iam.inventory.gcp_api2 import errors as api_errors
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class IAMClient(_base_client.BaseClient):
    """IAM Client."""

    API_NAME = 'iam'

    def __init__(self, global_configs=None, credentials=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            credentials (GoogleCredentials): Google credentials for auth-ing
                to the API.
        """

        super(IAMClient, self).__init__(
            global_configs, credentials=credentials, api_name=self.API_NAME)

        self.rate_limiter = RateLimiter(
            self.global_configs.get('max_iam_api_calls_per_second'),
            1)

    def get_serviceaccounts(self, project_id):
        """Get information about service account

        Args:
            project_id (str): The id of the project.

        Yields:
            dict: The response of retrieving the service account
        """
        endpoint = self.service.projects().serviceAccounts().list
        project_name = 'projects/{}'.format(project_id)

        next_token = ''
        while True:
            api_call = endpoint(name=project_name,
                                pageToken=next_token)

            try:
                result = self._execute(api_call, self.rate_limiter)
            except (errors.HttpError, HttpLib2Error) as e:
                LOGGER.error(api_errors.ApiExecutionError(project_name, e))
                # TODO: pass in "buckets" as resource_name variable
                raise api_errors.ApiExecutionError('serviceAccounts', e)

            # Does the result have any objects listed?
            if 'accounts' not in result:
                break

            # Yield objects
            for item in result['accounts']:
                yield item

            # Are we finished?
            if 'nextPageToken' not in result:
                break
            next_token = result['nextPageToken']

    def get_project_roles(self, project_id):
        """Get information about project roles

        Args:
            project_id (str): The id of the project.

        Yields:
            dict: The response of retrieving the project roles
        """
        endpoint = self.service.projects().roles().list
        org_name = 'projects/{}'.format(project_id)

        next_token = ''
        while True:
            api_call = endpoint(parent=org_name,
                                pageToken=next_token,
                                view='FULL')

            try:
                result = self._execute(api_call, self.rate_limiter)
            except (errors.HttpError, HttpLib2Error) as e:
                LOGGER.error(api_errors.ApiExecutionError(project_id, e))
                # TODO: pass in "buckets" as resource_name variable
                raise api_errors.ApiExecutionError('roles', e)

            # Does the result have any objects listed?
            if 'roles' not in result:
                break

            # Yield objects
            for item in result['roles']:
                yield item

            # Are we finished?
            if 'nextPageToken' not in result:
                break
            next_token = result['nextPageToken']

    def get_organization_roles(self, orgid):
        """Get information about organization roles

        Args:
            orgid (str): The id of the organization.

        Yields:
            dict: The response of retrieving the organization roles
        """
        endpoint = self.service.organizations().roles().list
        org_name = orgid

        next_token = ''
        while True:
            api_call = endpoint(parent=org_name,
                                pageToken=next_token,
                                view='FULL')

            result = self._execute(api_call, self.rate_limiter)

            # Does the result have any objects listed?
            if 'roles' not in result:
                break

            # Yield objects
            for item in result['roles']:
                yield item

            # Are we finished?
            if 'nextPageToken' not in result:
                break
            next_token = result['nextPageToken']

    def get_curated_roles(self, orgid):
        """Get information about curated roles

        Args:
            orgid (str): The id of the organization.

        Yields:
            dict: The response of retrieving the curated roles
        """
        endpoint = self.service.roles().list
        org_name = ''

        next_token = ''
        while True:
            api_call = endpoint(parent=org_name,
                                pageToken=next_token,
                                view='FULL')
            try:
                result = self._execute(api_call, self.rate_limiter)
            except (errors.HttpError, HttpLib2Error) as e:
                LOGGER.error(api_errors.ApiExecutionError(orgid, e))
                # TODO: pass in "buckets" as resource_name variable
                raise api_errors.ApiExecutionError('roles', e)

            # Does the result have any objects listed?
            if 'roles' not in result:
                break

            # Yield objects
            for item in result['roles']:
                yield item

            # Are we finished?
            if 'nextPageToken' not in result:
                break
            next_token = result['nextPageToken']
