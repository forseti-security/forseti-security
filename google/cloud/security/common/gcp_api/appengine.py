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

from googleapiclient import errors
from httplib2 import HttpLib2Error
from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors


class AppEngineRepository(_base_repository.BaseRepositoryClient):
    """AppEngine API Respository."""

    def __init__(self,
                 quota_max_calls=None,
                 quota_period=1.0,
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

        self._apps = None

        super(AppEngineRepository, self).__init__(
            'appengine', versions=['v1'],
            quota_max_calls=quota_max_calls,
            quota_period=quota_period,
            use_rate_limiter=use_rate_limiter)

    @property
    def apps(self):
        """An _AppEngineAppsRepository instance.

        Returns:
          object: An _AppEngineAppsRepository instance.
        """
        if not self._apps:
            self._apps = self._init_repository(
                _AppEngineAppsRepository,
                self.gcp_services['v1'],
                self._apps)

        return self._apps


class _AppEngineAppsRepository(
        _base_repository.GCPRepository,
        _base_repository.GetQueryMixin):
    """Implementation of AppEngine Apps repository."""

    def __init__(self, gcp_service, credentials, rate_limiter):
        """Constructor.

        Args:
          gcp_service (object): A GCE service object built using the Google
              discovery API.
          credentials (object): GoogleCredentials.
          rate_limiter (object): A rate limiter instance.
        """
        super(_AppEngineAppsRepository, self).__init__(
            gcp_service=gcp_service,
            credentials=credentials,
            key_field='appsId',
            component='apps',
            rate_limiter=rate_limiter)


class AppEngineClient(object):
    """AppEngine Client.

    https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps
    """
    # TODO: Remove pylint disable.
    DEFAULT_QUOTA_TIMESPAN_PER_SECONDS = 1  # pylint: disable=invalid-name

    def __init__(self, global_configs, **kwargs):
        """Initialize.

        Args:
            global_configs (dict): Forseti config.
            **kwargs (dict): The kwargs.
        """
        max_calls = global_configs.get('max_appengine_api_calls_per_second')
        self.repository = AppEngineRepository(
            quota_max_calls=max_calls,
            quota_period=self.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            use_rate_limiter=kwargs.get('use_rate_limiter', True))

    def get_app(self, project_id):
        """Gets information about an application.

        Args:
            project_id (str): The id of the project.

        Returns:
            dict: The response of retrieving the AppEngine app.
        """
        try:
            return self.repository.apps.get(project_id)
        except (errors.HttpError, HttpLib2Error) as e:
            if isinstance(e, errors.HttpError) and e.resp.status == 404:
                # TODO: handle error more gracefully
                # application not found
                return {}
            raise api_errors.ApiExecutionError(project_id, e)
