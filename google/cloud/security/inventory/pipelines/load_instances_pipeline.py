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


class LoadInstancesPipeline(base_pipeline.BasePipeline):
    """Load compute instances for all projects."""

    RESOURCE_NAME = 'instances'

    def _transform(self, resource_from_api):
        """Create an iterator of instances to load into database.

        Args:
            resource_from_api (dict): A dict of instances, keyed by
                project id, from GCP API.

        Yields:
            dict: Instance properties.
        """
        for (project_id, instances) in resource_from_api.iteritems():
            for instance in instances:
                yield {'resource_key': instance.get('id'),
                       'resource_type': 'INSTANCE',
                       'resource_data': parser.json_stringify(instance)

                       }

    def _retrieve(self):
        """Retrieve instances from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute instances for each.

        Returns:
            dict: A map of projects with their instances (list):
            {project_id: [instances]}
        """
        projects = (proj_dao
                    .ProjectDao(self.global_configs)
                    .get_projects(self.cycle_timestamp))
        instances = {}
        for project in projects:
            project_instances = self.safe_api_call('get_instances',
                                                   project.id)
            if project_instances:
                instances[project.id] = project_instances
        return instances

    def run(self):
        """Run the pipeline.

        Sometimes, can_forward_ip will be a None value, instead of strictly
        boolean.  This will cause MySQL to display the warning message:
        "Incorrect integer value: '' for column 'can_ip_forward at row N"
        on loading the data.  This can be safely ignored as the row will
        still be loaded with the can_ip_forward as 0 value.

        There is a fix for this here:
        https://stackoverflow.com/a/5968530/2830207
        But it will be hacky to implement, essentially a customized SQL
        statement and condition checking.  So, leaving the warning as is.

        Alternatively, can change this column type to varchar.  Then, cast it
        to boolean when retrieved on the forseti application side.
        """
        instances = self._retrieve()
        loadable_instances = self._transform(instances)
        self._load(self.RESOURCE_NAME, loadable_instances)
        self._get_loaded_count()
