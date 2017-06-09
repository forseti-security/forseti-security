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


class LoadAppenginePipeline(base_pipeline.BasePipeline):
    """Load all AppEngine applications for all projects."""

    def _retrieve(self):
        projects = proj_dao.ProjectDao().get_projects(self.cycle_timestamp)
        apps = []
        for project in projects:
            app = self.api_client.get_app(project.id)
            if app:
                apps.append(app)
        return apps

    def _transform(self):
        pass

    def run(self):
        """Run the pipeline."""
        apps = self._retrieve()

