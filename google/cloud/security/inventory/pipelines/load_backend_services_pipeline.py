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

"""Pipeline to load compute backend services into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadBackendServicesPipeline(base_pipeline.BasePipeline):
    """Load compute backend services for all projects."""

    RESOURCE_NAME = 'backend_services'

    def _transform(self, resource_from_api):
        """Create an iterator of backend services to load into database.

        Args:
            resource_from_api (dict): Forwarding rules, keyed by
                project id, from GCP API.

        Yields:
            iterator: backend service properties in a dict.
        """
        for (project_id, backend_services) in resource_from_api.iteritems():
            for backend_service in backend_services:
                yield {'resource_key': project_id,
                       'resource_type': 'BACKEND_SERVICE',
                       'resource_data': parser.json_stringify(backend_services)
                       }

    def _retrieve(self):
        """Retrieve backend services from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute backend services for each.

        Returns:
            dict: Mapping projects with their backend services (list):
            {project_id: [backend_services]}
        """
        projects = (proj_dao
                    .ProjectDao(self.global_configs)
                    .get_projects(self.cycle_timestamp))
        backend_services = {}
        for project in projects:
            project_backend_services = self.safe_api_call(
                'get_backend_services', project.id)
            if project_backend_services:
                backend_services[project.id] = project_backend_services

        return backend_services

    def run(self):
        """Run the pipeline."""
        forwarding_rules = self._retrieve()
        loadable_rules = self._transform(forwarding_rules)
        self._load(self.RESOURCE_NAME, loadable_rules)
        self._get_loaded_count()
