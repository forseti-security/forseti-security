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
"""Scanner for the firewall rule engine."""

from collections import defaultdict
import json

from google.cloud.forseti.common.gcp_type import firewall_rule
from google.cloud.forseti.common.gcp_type import resource as resource_type
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import firewall_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class FirewallPolicyScanner(base_scanner.BaseScanner):
    """Scanner for firewall data."""

    SCANNER_OUTPUT_CSV_FMT = 'scanner_output_firewall.{}.csv'

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Service configuration.
            model_name (str): name of the data model
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """

        super(FirewallPolicyScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = firewall_rules_engine.FirewallRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    @staticmethod
    def _flatten_violations(violations, rule_indices):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.
            rule_indices (dict): A dictionary of string rule ids to indices.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            violation_data = {'policy_names': violation.policy_names,
                              'recommended_actions': (
                                  violation.recommended_actions)}

            violation_dict = {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'resource_name': violation.resource_name,
                'full_name': violation.full_name,
                'rule_name': violation.rule_id,
                'rule_index': rule_indices.get(violation.rule_id, 0),
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'resource_data': violation.resource_data
            }
            sorted(violation_dict)
            yield violation_dict

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): A list of violations.
        """
        rule_indices = self.rules_engine.rule_book.rule_indices
        all_violations = self._flatten_violations(all_violations, rule_indices)
        self._output_results_to_db(list(all_violations))

    def _find_violations(self, policies):
        """Find violations in the policies.

        Args:
            policies (list): The list of policies to find violations in.

        Returns:
            list: A list of all violations
        """
        all_violations = []
        LOGGER.info('Finding firewall policy violations...')
        for resource_id, p_policies in policies.items():
            resource = resource_util.create_resource(
                resource_id=resource_id, resource_type='project')
            LOGGER.debug('%s => %s', resource, p_policies)
            violations = self.rules_engine.find_violations(
                resource, p_policies)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            dict: Dict of project to firewall policy data.
            dict: Dict of resource to resource count.
        """

        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        project_policies = defaultdict(list)
        count = -1
        with scoped_session as session:

            for cnt, i in enumerate(data_access.scanner_iter(
                    session, 'firewall')):
                count = cnt
                firewall_data_for_scanner = json.loads(i.data)
                firewall_data_for_scanner['project_id'] = i.parent.name
                firewall_data_for_scanner['full_name'] = i.full_name

                project_policies[i.parent.name].append(
                    firewall_rule.FirewallRule.from_dict(
                        firewall_dict=firewall_data_for_scanner,
                        project_id=i.parent.name,
                        validate=True))

        if count < 0:
            LOGGER.warn('No firewall policies found. Exiting.')
            return project_policies, {
                resource_type.ResourceType.FIREWALL_RULE: 0
            }

        resource_counts = {
            resource_type.ResourceType.FIREWALL_RULE: count + 1,
        }

        return project_policies, resource_counts

    def run(self):
        """Runs the data collection."""
        policy_data, _ = self._retrieve()
        all_violations = self._find_violations(policy_data)
        self._output_results(all_violations)
