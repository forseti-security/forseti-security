# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with azthe License.
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

# pylint: disable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import instance_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner
from google.cloud.security.scanner.audit import instance_network_interface_rules_engine
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class InstanceNetworkInterfaceScanner(base_scanner.BaseScanner):
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
        super(InstanceNetworkInterfaceScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)
        self.rules_engine = (
            instance_network_interface_rules_engine
            .InstanceNetworkInterfaceRulesEngine(
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
            violation_data['raw_data'] = violation.raw_data
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
        resource_name = 'violations'

        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(resource_name, all_violations)

    # pylint: disable=invalid-name
    def get_instance_networks_interfaces(self):
        """Get network info from a particular snapshot.

           Returns:
               list: A list of networks from a particular project

           Raises:
               MySQLError if a MySQL error occurs.
        """
        instances = instance_dao.InstanceDao(self.global_configs).get_instances(
            self.snapshot_timestamp)
        return [instance.create_network_interfaces() for instance in instances]

    @staticmethod
    def parse_instance_network_instance(instance_object):
        """Create a list of network interface obj.

        Args:
            instance_object (instance_object): an instance object

        Returns:
            list: a list of network interface objects
        """
        return instance_object.create_network_interfaces()

    def _get_project_policies(self):
        """Get projects from data source.

        Returns:
            dict: project policies
        """
        project_policies = {}
        project_policies = (
            project_dao
            .ProjectDao(self.global_configs)
            .get_project_policies('projects',
                                  self.
                                  snapshot_timestamp))
        return project_policies

    @staticmethod
    def _get_resource_count(project_policies, instance_network_interfaces):
        """Get resource count for org and project policies.

        Args:
            project_policies (dict): containing the projects
                (gcp_type.project.Project) and their iam policies (dict).
            instance_network_interfaces (list): of network_interface objects.

        Returns:
            dict: Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.INSTANCE: len(instance_network_interfaces),
        }

        return resource_counts

    def _retrieve(self):
        """Run the data collection.

        Return:
           list: instance_networks_interfaces
        """
        return self.get_instance_networks_interfaces()

    def _find_violations(self, enforced_networks_data):
        """Find violations in the policies.

            Args:
                enforced_networks_data (list): Enforced networks data
                    to find violations in

            Returns:
                list: A list of violations
        """
        all_violations = []
        LOGGER.info('Finding enforced networks violations...')
        for instance_network_interface in enforced_networks_data:
            LOGGER.debug('%s', instance_network_interface)
            violations = self.rules_engine.find_policy_violations(
                instance_network_interface)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def run(self):
        """Runs the data collection."""
        instance_network_interface_data = self._retrieve()
        all_violations = (
            self._find_violations(instance_network_interface_data))
        self._output_results(all_violations)
