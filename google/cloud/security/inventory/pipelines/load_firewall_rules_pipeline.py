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

"""Pipeline to load firewall rules into Inventory.

This pipeline depends on the LoadProjectsPipeline.
"""

from google.cloud.security.common.data_access import project_dao as proj_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.inventory.pipelines import base_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadFirewallRulesPipeline(base_pipeline.BasePipeline):
    """Load firewall rules for all projects."""

    RESOURCE_NAME = 'firewall_rules'

    def _transform(self, resource_from_api):
        """Transform firewall rules map into loadable format for Cloud SQL.

        Loading the project id as project number is not supported by the
        GCP firewall api.

        Args:
            resource_from_api (dict): A dict mapping projects with a list of
                their firewall rules.
                {project_id1: [firewall_rule1a, firewall_rule1b],
                 project_id2: [firewall_rule2a, firewall_rule2b],
                 project_id3: [firewall_rule3a, firewall_rule3b]}

        Yields:
            iterable: Loadable firewall rules as a per-firewall dictionary.
        """
        for project_id, firewall_rules in resource_from_api.iteritems():
            for firewall_rule in firewall_rules:
                yield {'project_id': project_id,
                       'resource_key': firewall_rule.get('name'),
                       'resource_type': 'FIREWALL_RULES',
                       'resource_data': parser.json_stringify(firewall_rule)}

   def _retrieve(self):
        """Retrieve firewall rules from GCP.

        Get all the projects in the current snapshot and retrieve the
        firewall rules for each.  Projects without firewalls will also be
        captured.

        Returns:
            dict: A dict mapping projects with a list of their firewall rules.
                {project_id1: [firewall_rule1a, firewall_rule1b],
                 project_id2: [firewall_rule2a, firewall_rule2b],
                 project_id3: [firewall_rule3a, firewall_rule3b]}
        """
        firewall_rules_map = {}
        projects = (proj_dao
                    .ProjectDao(self.global_configs)
                    .get_projects(self.cycle_timestamp))
        for project in projects:
            firewall_rules = self.safe_api_call('get_firewall_rules',
                                                project.id)
            if firewall_rules:
                firewall_rules_map[project.id] = firewall_rules
        return firewall_rules_map

    def run(self):
        """Run the pipeline."""
        firewall_rules_map = self._retrieve()
        loadable_firewall_rules = self._transform(firewall_rules_map)
        self._load(self.RESOURCE_NAME, loadable_firewall_rules)
        self._get_loaded_count()
