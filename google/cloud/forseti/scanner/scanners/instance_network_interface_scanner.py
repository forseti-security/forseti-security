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
from google.cloud.forseti.common.gcp_type import instance
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.scanner.audit import instance_network_interface_rules_engine
# pylint: enable=line-too-long

LOGGER = logger.get_logger(__name__)


class InstanceNetworkInterfaceScanner(base_scanner.BaseScanner):
    """Pipeline to network enforcer from DAO."""

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
        super(InstanceNetworkInterfaceScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
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
            violation_data = {'project': violation.project,
                              'full_name': violation.full_name,
                              'network': violation.network, 'ip': violation.ip,
                              'resource_data': violation.resource_data}
            yield {
                'resource_name': violation.resource_name,
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
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
        """Retrieve the network interfaces for vm instances.

        Return:
           list: A list that contains nested lists of per-instance
               InstanceNetworksInterface objects.
        """

        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            network_interfaces = []

            for instance_from_data_model in data_access.scanner_iter(
                    session, 'instance'):

                proj = project.Project(
                    project_id=instance_from_data_model.parent.name,
                    full_name=instance_from_data_model.parent.full_name,
                )
                ins = instance.Instance.from_json(
                    parent=proj,
                    json_string=instance_from_data_model.data)
                network_interfaces.append(ins.create_network_interfaces())

        if not network_interfaces:
            LOGGER.warn('No VM network interfaces found. Exiting.')
            return None, 0

        return network_interfaces

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
            violations = self.rules_engine.find_violations(
                instance_network_interface)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def run(self):
        """Runs the instance network interface scanner."""
        network_interfaces = self._retrieve()
        all_violations = self._find_violations(network_interfaces)
        self._output_results(all_violations)
