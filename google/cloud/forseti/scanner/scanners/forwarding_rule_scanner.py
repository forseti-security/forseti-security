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
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.common.data_access import forwarding_rules_dao
from google.cloud.forseti.scanner.audit import forwarding_rule_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class ForwardingRuleScanner(base_scanner.BaseScanner):
    """Pipeline for forwarding rules from dao"""

    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(ForwardingRuleScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)

        self.rules_engine = forwarding_rule_rules_engine.\
            ForwardingRuleRulesEngine(
                rules_file_path=self.rules,
                snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    def run(self):
        forwarding_rules = self._retrieve()
        all_violations = self._find_violations(forwarding_rules)
        self._output_results(all_violations)

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each RuleViolation member.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            violation_data = {}
            violation_data['violation_type'] = violation.violation_type
            violation_data['target'] = violation.target
            violation_data['load_balancing_scheme'] = \
                violation.load_balancing_scheme
            violation_data['port'] = violation.port
            violation_data['port_range'] = violation.port_range
            violation_data['ip_protocol'] = violation.ip_protocol
            violation_data['ip_address'] = violation.ip_address
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.violation_type,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
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
        forwarding_rules = forwarding_rules_dao \
            .ForwardingRulesDao(self.global_configs) \
            .get_forwarding_rules(self.snapshot_timestamp)
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
            violations = self.rules_engine.find_policy_violations(
                forwarding_rule)
            LOGGER.debug(violations)
            if violations is not None:
                all_violations.append(violations)
        return all_violations
