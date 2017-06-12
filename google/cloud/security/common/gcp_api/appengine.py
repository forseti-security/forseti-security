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

import gflags as flags

from google.cloud.security.common.gcp_api import _base_client
from googleapiclient.errors import HttpError

FLAGS = flags.FLAGS

flags.DEFINE_integer('max_appengine_api_calls_per_second', 20,
                     'AppEngine API calls per seconds.')

class AppEngineClient(_base_client.BaseClient):
    """AppEngine Client.

    https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps
    """

    API_NAME = 'appengine'

    def __init__(self, credentials=None, version=None):
        super(AppEngineClient, self).__init__(
            credentials=credentials, api_name=self.API_NAME, version=version)

    def get_app(self, project_id):
        """Gets information about an application.
        """
        apps = self.service.apps()
        app = None
        request = apps.get(appsId=project_id)
        try:
            app = request.execute()
        except HttpError as e:
            resp = e.resp
            # TODO: use resp.status code to determine error state
            if resp.status == '404':
                # application not found
                pass
            if resp.status == '403':
                # Operation not allowed
                pass
        return app
