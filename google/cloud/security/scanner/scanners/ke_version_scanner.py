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

from google.cloud.security.common.data_access import ke_dao
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import ke_version_rules_engine
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class KeVersionScanner(base_scanner.BaseScanner):
    """Check if the version of running KE clusters and nodes are allowed."""

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(KeVersionScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)
        self.rules_engine = ke_version_rules_engine.KeVersionRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
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
                'node_pool_name': violation.node_pool_name
            }
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
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
        ke_clusters = (ke_dao.KeDao(self.global_configs)
                       .get_clusters(self.snapshot_timestamp))

        return ke_clusters

    def run(self):
        ke_clusters = self._retrieve()
        all_violations = self._find_violations(ke_clusters)
        self._output_results(all_violations)
