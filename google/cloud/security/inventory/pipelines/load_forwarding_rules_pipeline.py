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

"""Pipeline to load compute forwarding rules into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from dateutil import parser as dateutil_parser

from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadForwardingRulesPipeline(base_pipeline.BasePipeline):
    """Load compute forwarding rules for all projects."""

    RESOURCE_NAME = 'forwarding_rules'

    def _transform(self, project_fwd_rules):
        """Create an iterator of forwarding rules to load into database.

        TODO: truncate the region and target.

        Args:
            project_fwd_rules: A dict of forwarding rules, keyed by
                project id, from GCP API.

        Yields:
            Iterator of forwarding rule properties in a dict.
        """
        for (project_id, forwarding_rules) in project_fwd_rules.iteritems():
            for rule in forwarding_rules:
                fr_create_time = rule.get('creationTimestamp')
                try:
                    create_time = (
                        dateutil_parser
                        .parse(fr_create_time)
                        .strftime(self.MYSQL_DATETIME_FORMAT))
                except (TypeError, ValueError) as e:
                    LOGGER.error(
                        'Unable to parse creation_timestamp from '
                        'forwarding rule: %s\n%s', fr_create_time, e)
                    create_time = None

                yield {'project_id': project_id,
                       'id': rule.get('id'),
                       'creation_timestamp': create_time,
                       'name': rule.get('name'),
                       'description': rule.get('description'),
                       'region': rule.get('region'),
                       'ip_address': rule.get('IPAddress'),
                       'ip_protocol': rule.get('IPProtocol'),
                       'port_range': rule.get('portRange'),
                       'ports': rule.get('ports', []),
                       'target': rule.get('target'),
                       'load_balancing_scheme': rule.get('loadBalancingScheme'),
                       'subnetwork': rule.get('subnetwork'),
                       'network': rule.get('network'),
                       'backend_service': rule.get('backendService')}

    def _retrieve(self):
        """Retrieve forwarding rules from GCP.

        Get all the projects in the current snapshot and retrieve the
        compute forwarding rules for each.

        Returns:
            A dict mapping projects with their forwarding rules (list):
            {project_id: [forwarding_rules]}
        """
        projects = proj_dao.ProjectDao().get_projects(self.cycle_timestamp)
        forwarding_rules = {}
        for project in projects:
            project_fwd_rules = []
            try:
                response = self.api_client.get_forwarding_rules(project.id)
                for page in response:
                    items = page.get('items', {})
                    for region_fwd_rules in items.values():
                        fwd_rules = region_fwd_rules.get('forwardingRules', [])
                        project_fwd_rules.extend(fwd_rules)
            except api_errors.ApiExecutionError as e:
                LOGGER.error(inventory_errors.LoadDataPipelineError(e))
            if project_fwd_rules:
                forwarding_rules[project.id] = project_fwd_rules
        return forwarding_rules

    def run(self):
        """Run the pipeline."""
        forwarding_rules = self._retrieve()
        loadable_rules = self._transform(forwarding_rules)
        self._load(self.RESOURCE_NAME, loadable_rules)
        self._get_loaded_count()
