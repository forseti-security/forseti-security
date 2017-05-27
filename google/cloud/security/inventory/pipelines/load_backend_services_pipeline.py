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

"""Pipeline to load compute backend services into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadBackendServicesPipeline(base_pipeline.BasePipeline):
    """Load compute backend services for all projects."""

    RESOURCE_NAME = 'backend_services'

    def _transform(self, resource_from_api):
        """Create an iterator of backend services to load into database.

        Args:
            resource_from_api: A dict of forwarding rules, keyed by
                project id, from GCP API.

        Yields:
            Iterator of backend service properties in a dict.
        """
        for (project_id, backend_services) in resource_from_api.iteritems():
            for backend_service in backend_services:
                yield {'project_id': project_id,
                       'id': backend_service.get('id'),
                       'creation_timestamp': parser.format_timestamp(
                           backend_service.get('creationTimestamp'),
                           self.MYSQL_DATETIME_FORMAT),
                       'name': backend_service.get('name'),
                       'description': backend_service.get('description'),
                       'affinity_cookie_ttl_sec': backend_service.get(
                           'affinityCookieTtlSec'),
                       'backends': parser.json_stringify(
                           backend_service.get('backends', [])),
                       'cdn_policy': parser.json_stringify(
                           backend_service.get('cdnPolicy', {})),
                       'connection_draining': parser.json_stringify(
                           backend_service.get('connectionDraining', {})),
                       'enable_cdn': (
                           1 if backend_service.get('enableCDN') else 0),
                       'health_checks': parser.json_stringify(
                           backend_service.get('healthChecks', [])),
                       'iap': parser.json_stringify(
                           backend_service.get('iap', {})),
                       'load_balancing_scheme': backend_service.get(
                           'loadBalancingScheme'),
                       'port': backend_service.get('port'),
                       'port_name': backend_service.get('portName'),
                       'protocol': backend_service.get('protocol'),
                       'region': backend_service.get('region'),
                       'session_affinity': backend_service.get(
                           'sessionAffinity'),
                       'timeout_sec': backend_service.get('timeoutSec')}

    def _retrieve(self):
        """Retrieve backend services from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute backend services for each.

        Returns:
            A dict mapping projects with their backend services (list):
            {project_id: [backend_services]}
        """
        projects = proj_dao.ProjectDao().get_projects(self.cycle_timestamp)
        backend_services = {}
        for project in projects:
            project_backend_services = []
            try:
                response = self.api_client.get_backend_services(project.id)
                for page in response:
                    items = page.get('items', {})
                    for region_backend_services in items.values():
                        rbs = region_backend_services.get(
                            'backendServices', [])
                        project_backend_services.extend(rbs)
            except api_errors.ApiExecutionError as e:
                LOGGER.error(inventory_errors.LoadDataPipelineError(e))
            if project_backend_services:
                backend_services[project.id] = project_backend_services
        return backend_services

    def run(self):
        """Run the pipeline."""
        forwarding_rules = self._retrieve()
        loadable_rules = self._transform(forwarding_rules)
        self._load(self.RESOURCE_NAME, loadable_rules)
        self._get_loaded_count()
