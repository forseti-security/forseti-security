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

"""Scanner for the Networks Enforcer acls rules engine."""

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import instance_dao
from google.cloud.security.scanner.scanners import base_scanner
from google.cloud.security.scanner.audit import blacklist_rules_engine


LOGGER = log_util.get_logger(__name__)


class BlacklistScanner(base_scanner.BaseScanner):
    """Pipeline to network enforcer from DAO."""

    def __init__(self, global_configs, scanner_configs,
                 snapshot_timestamp, rules):
        """Initialization.

         Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(BlacklistScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)
        self.rules_engine = (
            blacklist_rules_engine
            .BlacklistRulesEngine(
                rules_file_path=self.rules,
                snapshot_timestamp=self.snapshot_timestamp))
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
            violation_data = {}
            violation_data['project'] = violation.project
            violation_data['network'] = violation.network
            violation_data['ip'] = violation.ip
            yield {
                'resource_id': 'instance_network_interface',
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

        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    # pylint: disable=invalid-name
    def get_instance_networks_interfaces(self):
        """Get network info from a particular snapshot.

           Returns:
               list: A list of networks from a particular project
        """

        instances = instance_dao.InstanceDao(self.global_configs).get_instances(
            self.snapshot_timestamp)
        network_interfaces = []
        for instance in instances:
            network_interfaces += instance.create_network_interfaces()
        return network_interfaces

    def _retrieve(self):
        """Run the data collection.

        Return:
           list: instance_networks_interfaces
        """
        return self.get_instance_networks_interfaces()

    def _find_violations(self, instances_networks_data):
        """Find violations in the policies.

            Args:
                instances_networks_data (list): instance networks data
                    to find violations in

            Returns:
                list: A list of violations
        """
        all_violations = []
        LOGGER.info('Finding blacklisted ip addresses...')
        for instance_network_interface in instances_networks_data:
            LOGGER.debug('%s', instance_network_interface)
            violations = self.rules_engine.find_policy_violations(
                instance_network_interface)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def run(self):
        """Runs scanning."""
        instances_network_interface_data = self._retrieve()
        all_violations = (
            self._find_violations(instances_network_interface_data))
        self._output_results(all_violations)
