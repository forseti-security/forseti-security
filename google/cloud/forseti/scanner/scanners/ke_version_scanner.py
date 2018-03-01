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

"""Scanner for the KE version rules engine."""

from google.cloud.forseti.common.gcp_type.ke_cluster import KeCluster
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import ke_version_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class KeVersionScanner(base_scanner.BaseScanner):
    """Check if the version of running KE clusters and nodes are allowed."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, audit_invocation_time, rules):
      """Initialization.

      Args:
          global_configs (dict): Global configurations.
          scanner_configs (dict): Scanner configurations.
          service_config (ServiceConfig): Forseti 2.0 service configs
          model_name (str): name of the data model
          audit_invocation_time (str): The id of a given scanner run (timestamp)
          rules (str): Fully-qualified path and filename of the rules file.
      """
        super(KeVersionScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            audit_invocation_time,
            rules)

        self.rules_engine = ke_version_rules_engine.KeVersionRulesEngine(
            rules_file_path=self.rules)
        self.rules_engine.build_rule_book(self.global_configs)

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            violation_data = {
                'violation_reason': violation.violation_reason,
                'project_id': violation.project_id,
                'cluster_name': violation.cluster_name,
                'full_name': violation.full_name,
                'node_pool_name': violation.node_pool_name
            }
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'inventory_data': violation.inventory_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations
        """
        all_violations = list(self._flatten_violations(all_violations))
        self._output_results_to_db(all_violations)

    def _find_violations(self, ke_clusters):
        """Find violations in the policies.

        Args:
            ke_clusters (list): Clusters to find violations in.

        Returns:
            list: All violations.
        """
        all_violations = []
        LOGGER.info('Finding ke cluster version violations...')

        for ke_cluster in ke_clusters:
            violations = self.rules_engine.find_policy_violations(
                ke_cluster)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Runs the data collection.

        Returns:
            list: KE Cluster data.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            ke_clusters = []
            for ke_cluster in data_access.scanner_iter(
                    session, 'kubernetes_cluster'):
                service_config = list(data_access.scanner_iter(
                    session, 'kubernetes_service_config',
                    parent_type_name=ke_cluster.type_name))[0]

                project_id = ke_cluster.parent.name
                ke_clusters.append(
                    KeCluster.from_json(project_id,
                                        service_config.data,
                                        ke_cluster.data,
                                        ke_cluster.parent.full_name))

        return ke_clusters

    def run(self):
        ke_clusters = self._retrieve()
        all_violations = self._find_violations(ke_clusters)
        self._output_results(all_violations)
