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

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class IAMClient(_base_client.BaseClient):
    """IAM Client."""

    API_NAME = 'iam'

    def __init__(self, global_configs, credentials=None, version=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            credentials (GoogleCredentials): Google credentials for auth-ing
                to the API.
        """

        super(IAMClient, self).__init__(
            global_configs, credentials=credentials, api_name=self.API_NAME, version=version)

        self.rate_limiter = RateLimiter(
            self.global_configs.get('max_iam_api_calls_per_second'),
            1)

    def get_service_accounts(self, project_id):
        endpoint = self.service.projects().serviceAccounts().list
        project_name = 'projects/{}'.format(project_id)

        next_token = ''
        while True:
            api_call = endpoint(name=project_name,
                                pageToken=next_token)

            try:
                result = api_call.execute()
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

    def get_service_account_keys(self, service_account_name):
        endpoint = self.service.projects().serviceAccounts().keys().list
        api_call = endpoint(name=service_account_name)
        try:
            result = api_call.execute()
        except (errors.HttpError, HttpLib2Error) as e:
            LOGGER.error(api_errors.ApiExecutionError(service_account_name, e))
            raise api_errors.ApiExecutionError('serviceAccountKeys', e)
        return result
