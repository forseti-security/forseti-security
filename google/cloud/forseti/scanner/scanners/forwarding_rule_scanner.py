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

"""Scanner for the Forwarding Rules rules engine."""
from google.cloud.forseti.common.gcp_type.forwarding_rule import ForwardingRule
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import forwarding_rule_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)


class ForwardingRuleScanner(base_scanner.BaseScanner):
    """Pipeline for forwarding rules from dao"""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp, rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(ForwardingRuleScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)

        self.rules_engine = forwarding_rule_rules_engine.\
            ForwardingRuleRulesEngine(
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
            violation_data = {'full_name': violation.full_name,
                              'violation_type': violation.violation_type,
                              'target': violation.target,
                              'load_balancing_scheme': (
                                  violation.load_balancing_scheme),
                              'port': violation.port,
                              'port_range': violation.port_range,
                              'ip_protocol': violation.ip_protocol,
                              'ip_address': violation.ip_address}
            yield {
                'resource_id': violation.resource_id,
                'resource_name': violation.resource_name,
                'full_name': violation.full_name,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.violation_type,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'resource_data': violation.resource_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _retrieve(self):
        """Runs the data collection.

        Returns:
            list: forwarding rule list.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            forwarding_rules = []
            for forwarding_rule in data_access.scanner_iter(
                    session, 'forwardingrule'):
                project_id = forwarding_rule.parent.name
                forwarding_rules.append(
                    ForwardingRule.from_json(
                        project_id, forwarding_rule.full_name,
                        forwarding_rule.data))

        return forwarding_rules

    def _find_violations(self, forwarding_rules):
        """Find violations in forwarding rules.

        Args:
            forwarding_rules (list): Forwarding rule to find violations in

         Returns:
            list: A list of forwarding rule violations
        """
        all_violations = []
        LOGGER.info('Finding Forwarding Rule Violations...')
        for forwarding_rule in forwarding_rules:
            LOGGER.debug('%s', forwarding_rule)
            violations = self.rules_engine.find_violations(
                forwarding_rule)
            LOGGER.debug(violations)
            if violations is not None:
                all_violations.append(violations)
        return all_violations

    def run(self):
        """Run, the entry point for this scanner."""
        forwarding_rules = self._retrieve()
        all_violations = self._find_violations(forwarding_rules)
        self._output_results(all_violations)
