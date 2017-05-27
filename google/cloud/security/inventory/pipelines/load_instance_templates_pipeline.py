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

"""Pipeline to load compute instance templates into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadInstanceTemplatesPipeline(base_pipeline.BasePipeline):
    """Load compute instance templates for all projects."""

    RESOURCE_NAME = 'instance_templates'

    def _transform(self, resource_from_api):
        """Create an iterator of instance templates to load into database.

        Args:
            resource_from_api: A dict of instance templates, keyed by
                project id, from GCP API.

        Yields:
            Iterator of instance template properties in a dict.
        """
        for (project_id, instance_templates) in resource_from_api.iteritems():
            for instance_template in instance_templates:
                yield {'project_id': project_id,
                       'id': instance_template.get('id'),
                       'creation_timestamp': parser.format_timestamp(
                           instance_template.get('creationTimestamp'),
                           self.MYSQL_DATETIME_FORMAT),
                       'name': instance_template.get('name'),
                       'description': instance_template.get('description'),
                       'properties': parser.json_stringify(
                           instance_template.get('properties', {}))}

    def _retrieve(self):
        """Retrieve instance templates from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute instance templates for each.

        Returns:
            A dict mapping projects with their instance templates (list):
            {project_id: [instance templates]}
        """
        projects = proj_dao.ProjectDao().get_projects(self.cycle_timestamp)
        instance_templates = {}
        for project in projects:
            project_instance_templates = []
            try:
                response = self.api_client.get_instance_templates(project.id)
                for page in response:
                    project_instance_templates.extend(page.get('items', []))
            except api_errors.ApiExecutionError as e:
                LOGGER.error(inventory_errors.LoadDataPipelineError(e))
            if project_instance_templates:
                instance_templates[project.id] = project_instance_templates
        return instance_templates

    def run(self):
        """Run the pipeline."""
        instance_templates = self._retrieve()
        loadable_instance_templates = self._transform(instance_templates)
        self._load(self.RESOURCE_NAME, loadable_instance_templates)
        self._get_loaded_count()
