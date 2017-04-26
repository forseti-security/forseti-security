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

"""Pipeline to load projects data into Inventory."""

import json

from dateutil import parser as dateutil_parser

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadProjectsPipeline(base_pipeline.BasePipeline):
    """Pipeline to load project data into Inventory."""

    RESOURCE_NAME = 'projects'

    MYSQL_DATETIME_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _transform(self, projects):
        """Yield an iterator of loadable iam policies.

        Args:
            projects: An iterable of resource manager project list response.
                https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body

        Yields:
            An iterable of loadable projects, as a per-project dictionary.
        """
        for project in (project for d in projects \
                        for project in d.get('projects', [])):
            project_json = json.dumps(project)
            try:
                parsed_time = dateutil_parser.parse(project.get('createTime'))
                formatted_project_create_time = (
                    parsed_time.strftime(self.MYSQL_DATETIME_FORMAT))
            except (TypeError, ValueError) as e:
                LOGGER.error(
                    'Unable to parse create_time from project: %s\n%s',
                    project.get('createTime', ''), e)
                formatted_project_create_time = '0000-00-00 00:00:00'

            yield {'project_number': project.get('projectNumber'),
                   'project_id': project.get('projectId'),
                   'project_name': project.get('name'),
                   'lifecycle_state': project.get('lifecycleState'),
                   'parent_type': project.get('parent', {}).get('type'),
                   'parent_id': project.get('parent', {}).get('id'),
                   'raw_project': project_json,
                   'create_time': formatted_project_create_time}

    def _retrieve(self):
        """Retrieve the project resources from GCP.

        Returns:
            An iterable of resource manager project list response.
            https://cloud.google.com/resource-manager/reference/rest/v1/projects/list#response-body
        """
        try:
            return self.api_client.get_projects(
                self.RESOURCE_NAME,
                lifecycleState=LifecycleState.ACTIVE)
        except api_errors.ApiExecutionError as e:
            raise inventory_errors.LoadDataPipelineError(e)

    def run(self):
        """Runs the data pipeline."""
        projects_map = self._retrieve()

        loadable_projects = self._transform(projects_map)

        self._load(self.RESOURCE_NAME, loadable_projects)

        self._get_loaded_count()
