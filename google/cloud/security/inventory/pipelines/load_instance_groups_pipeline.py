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

"""Pipeline to load compute instance groups into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadInstanceGroupsPipeline(base_pipeline.BasePipeline):
    """Load compute instance groups for all projects."""

    RESOURCE_NAME = 'instance_groups'

    def _transform(self, resource_from_api):
        """Create an iterator of instance groups to load into database.

        Args:
            resource_from_api: A dict of instance groups, keyed by
                project id, from GCP API.

        Yields:
            Iterator of instance group properties in a dict.
        """
        for (project_id, instance_groups) in resource_from_api.iteritems():
            for instance_group in instance_groups:
                yield {'project_id': project_id,
                       'id': instance_group.get('id'),
                       'creation_timestamp': parser.format_timestamp(
                           instance_group.get('creationTimestamp'),
                           self.MYSQL_DATETIME_FORMAT),
                       'name': instance_group.get('name'),
                       'description': instance_group.get('description'),
                       'named_ports': parser.json_stringify(
                           instance_group.get('namedPorts', [])),
                       'network': instance_group.get('network'),
                       'region': instance_group.get('region'),
                       'size': instance_group.get('size'),
                       'subnetwork': instance_group.get('subnetwork'),
                       'zone': instance_group.get('zone')}

    def _retrieve(self):
        """Retrieve instance groups from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute instance groups for each.

        Returns:
            A dict mapping projects with their instance groups (list):
            {project_id: [instance groups]}
        """
        projects = proj_dao.ProjectDao().get_projects(self.cycle_timestamp)
        igs = {}
        for project in projects:
            project_igs = []
            try:
                response = self.api_client.get_instance_groups(project.id)
                for page in response:
                    items = page.get('items', {})
                    for zone_igs in items.values():
                        zig_items = zone_igs.get(
                            'instanceGroups', [])
                        project_igs.extend(zig_items)
            except api_errors.ApiExecutionError as e:
                LOGGER.error(inventory_errors.LoadDataPipelineError(e))
            if project_igs:
                igs[project.id] = project_igs
        return igs

    def run(self):
        """Run the pipeline."""
        igs = self._retrieve()
        loadable_igs = self._transform(igs)
        self._load(self.RESOURCE_NAME, loadable_igs)
        self._get_loaded_count()
