# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Wrapper for AppEngine API client."""

from ratelimiter import RateLimiter

from google.cloud.security.common.gcp_api import _base_client
from apiclient import errors


class AppEngineClient(_base_client.BaseClient):
    """AppEngine Client.

    https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps
    """

    API_NAME = 'appengine'

    # TODO: Remove pylint disable.
    # pylint: disable=invalid-name
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 1
    # pylint: enable=invalid-name

    def __init__(self, global_configs, credentials=None, version=None):
        """Initialize.

        Args:
            global_configs (dict): Global configurations.
            credentials (GoogleCredentials): Google credentials.
            version (str): The version.
        """
        super(AppEngineClient, self).__init__(
            global_configs,
            credentials=credentials,
            api_name=self.API_NAME,
            version=version)

        self.rate_limiter = RateLimiter(
            self.global_configs.get('max_appengine_api_calls_per_second'),
            self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS)

    def get_app(self, project_id):
        """Gets information about an application.

        Args:
            project_id (str): The id of the project.

        Returns:
            dict: The response of retrieving the AppEngine app.
        """
        apps = self.service.apps()
        app = None
        request = apps.get(appsId=project_id)
        try:
            app = self._execute(request, self.rate_limiter)
        except errors.HttpError as e:
            resp = e.resp
            if resp.status == '404':
                # TODO: handle error more gracefully
                # application not found
                pass
            if resp.status == '403':
                # Operation not allowed
                # This has been handled by the BaseClient._execute
                pass
        return app
