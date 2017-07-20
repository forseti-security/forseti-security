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

"""Wrapper for SQL API client."""

from httplib2 import HttpLib2Error
from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from apiclient.errors import HttpError


LOGGER = log_util.get_logger(__name__)


class CloudsqlClient(_base_client.BaseClient):
    """CloudSQL Client."""

    API_NAME = 'sqladmin'
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 100  # pylint: disable=invalid-name

    def __init__(self, global_configs, credentials=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            credentials (GoogleCredentials): Google credentials for auth-ing
                to the API.
        """
        super(CloudsqlClient, self).__init__(
            global_configs, credentials=credentials, api_name=self.API_NAME)

        self.rate_limiter = RateLimiter(
            self.global_configs.get('max_sqladmin_api_calls_per_100_seconds'),
            self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def get_instances(self, project_id):
        """Gets all CloudSQL instances for a project.

        Args:
            project_id (int): The project id for a GCP project.

        Returns:
            dict: If successful, this function returns a dictionary for the
                instances in the project.
            {
              "kind": "sql#instancesList",
              "nextPageToken": string,
              "items": [
                instances Resource
              ]
            }

        Raises:
            ApiExecutionError: ApiExecutionError is raised if the call to the
                GCP ClodSQL API fails
        """
        instances_api = self.service.instances()
        try:
            instances_request = instances_api.list(project=project_id)
            instances = self._execute(instances_request, self.rate_limiter)
            return instances
        except (HttpError, HttpLib2Error) as e:
            LOGGER.error(api_errors.ApiExecutionError(project_id, e))
            raise api_errors.ApiExecutionError('instances', e)
