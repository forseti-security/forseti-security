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

"""Pipeline to load appengine applications into Inventory."""

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadAppenginePipeline(base_pipeline.BasePipeline):
    """Load all AppEngine applications for all projects."""

    RESOURCE_NAME = 'appengine'

    def _retrieve(self):
        """Retrieve AppEngine applications from GCP.

        Get all the projects in the current snapshot and retrieve the
        AppEngine applications for each.

        Returns:
            dict: Mapping projects with their AppEngine applications:
            {index: application}
        """
        projects = (
            proj_dao
            .ProjectDao(self.global_configs)
            .get_projects(self.cycle_timestamp))
        apps = {}
        for project in projects:
            app = self.safe_api_call('get_app', project.id)
            if app:
                apps[project.id] = app
        return apps

    def _transform(self, resource_from_api):
        """Create an iterator of AppEngine applications to load into database.

        Args:
            resource_from_api (dict): AppEngine applications, keyed by
                project id, from GCP API.

        Yields:
            iterator: AppEngine applications in a dict.
        """
        for index, app in resource_from_api.iteritems():
            yield {
                   'resource_key': app.get('name'),
                   'resource_type': 'APPENGINE_PIPELINE',
                   'resource_data': parser.json_stringify(app)}

    def run(self):
        """Run the pipeline."""
        apps = self._retrieve()
        loadable_apps = self._transform(apps)
        self._load(self.RESOURCE_NAME, loadable_apps)
        self._get_loaded_count()
