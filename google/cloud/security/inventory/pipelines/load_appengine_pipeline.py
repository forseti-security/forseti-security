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

"""Pipeline to load appengine applications into Inventory.
"""

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadAppEngineApplicationsPipeline(base_pipeline.BasePipeline):
    """Load all AppEngine applications for all projects."""

    def _retrieve(self):
        pass

    def _transform(self):
        pass

    def run(self):
        """Run the pipeline."""
        pass


# Liang's temp class
from google.cloud.security.common.gcp_api import _base_client
from oauth2client.client import GoogleCredentials
from googleapiclient.errors import HttpError

class AppEngine(_base_client.BaseClient):
    """AppEngine Client.

    https://cloud.google.com/appengine/docs/admin-api/reference/rest/v1/apps
    """

    API_NAME = 'appengine'
    
    def __init__(self, credentials=None, version=None):
        super(AppEngine, self).__init__(
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

def try_retrieve_apps(cycle_timestamp):
    projects = proj_dao.ProjectDao().get_projects(cycle_timestamp)
    apps = []
    appengine = AppEngine()
    for project in projects:
        app = appengine.get_app(project.id)
        if app:
            apps.append(app)
    import pprint
    pprint.pprint(apps)

if __name__ == '__main__':
    import sys
    try_retrieve_apps(sys.argv[1])
