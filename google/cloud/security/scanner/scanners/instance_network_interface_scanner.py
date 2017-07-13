# Copyright 2017 Google Inc.
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
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class InstanceNetworkInterfaceScanner(base_scanner.BaseScanner):
    """Pipeline to network enforcer from DAO."""

    def __init__(self, global_configs, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(InstanceNetworkInterfaceScanner, self).__init__(
            global_configs,
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def get_instance_networks_interfaces(self):
        """Get network info from a particular snapshot.

           Returns:
               A list of networks from a particular project

           Raises:
               MySQLError if a MySQL error occurs.
        """
        instances = instance_dao.InstanceDao().get_instances(
            self.snapshot_timestamp)
        network_interfaces = []
        for instance in instances:
            network_interfaces += instance.create_network_interfaces()
        return network_interfaces

    def parse_instance_network_instance(self, instance_object):
        """Create a list of network interface obj."""
        return instance_object.create_network_interfaces()

    def _get_project_policies(self):
        """Get projects from data source."""
        project_policies = {}
        project_policies = (
            project_dao.ProjectDao().get_project_policies('projects',
                                                          self.
                                                          snapshot_timestamp))
        return project_policies

    @staticmethod
    def _get_resource_count(project_policies, instance_network_interfaces):
        """Get resource count for org and project policies.

        Args:
            project_policies: dict containing the projects
                (gcp_type.project.Project) and their iam policies (dict).
            instance_network_interfaces: list of network_interface objects. 
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.INSTANCE: len(instance_network_interfaces),
        }

        return resource_counts

    def run(self):
        """Run the data collection."""
        enforced_networks_data = []
        project_policies = {}
        instance_network_interfaces = self.get_instance_networks_interfaces()
        enforced_networks_data.append(instance_network_interfaces)
        enforced_networks_data.append(project_policies)

        resource_counts = self._get_resource_count(project_policies,
                                                   instance_network_interfaces)

        return enforced_networks_data, resource_counts

    def find_violations(self, enforced_networks_data, rules_engine):
        """Find violations in the policies.

        Args:
            enforced_networks_data: Enforced networks data
            to find violations in
            rules_engine: The rules engine to run.

        Returns:
            A list of violations
        """
        all_violations = []
        LOGGER.info('Finding enforced networks violations...')
        for instance_network_interface in enforced_networks_data:
            LOGGER.debug('%s', instance_network_interface)
            violations = rules_engine.find_policy_violations(
                instance_network_interface)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

