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

"""Pipeline to load compute instances into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadInstanceGroupManagersPipeline(base_pipeline.BasePipeline):
    """Load compute instance group managers for all projects."""

    RESOURCE_NAME = 'instance_group_managers'

    def _transform(self, resource_from_api):
        """Create an iterator of instance group managers to load into database.

        Args:
            resource_from_api (dict): Instance group managers, keyed by
                project id, from GCP API.

        Yields:
            iterator: instance group manager properties in a dict.
        """
        for (project_id, igms) in resource_from_api.iteritems():
            for igm in igms:
                yield {'resource_key': igm.get('id'),
                       'resource_type': 'INSTANCE_GROUP_MANAGERS',
                       'resource_data': parser.json_stringify(igm)
                       }

    def _retrieve(self):
        """Retrieve instance group managers from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute instance group managers for each.

        Returns:
            dict: Mapping projects with their instance group managers (list):
                {project_id: [instance group managers]}
        """
        projects = (proj_dao
                    .ProjectDao(self.global_configs)
                    .get_projects(self.cycle_timestamp))
        igms = {}
        for project in projects:
            project_igms = self.safe_api_call('get_instance_group_managers',
                                              project.id)
            if project_igms:
                igms[project.id] = project_igms
        return igms

    def run(self):
        """Run the pipeline."""
        igms = self._retrieve()
        loadable_igms = self._transform(igms)
        self._load(self.RESOURCE_NAME, loadable_igms)
        self._get_loaded_count()
