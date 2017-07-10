# Copyright 2017 Google Inc.
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
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type import instance_network_interface as ini
from google.cloud.security.scanner.audit import instance_network_interface_rules_engine
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class InstanceNetworkInterfaceScanner(base_scanner.BaseScanner):
    """Pipeline to network enforcer from DAO"""
    def __init__(self, global_configs, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
<<<<<<< HEAD
        super(InstanceNetworkInterfaceScanner, self).__init__(
            global_configs,
            snapshot_timestamp)
        self.global_configs = global_configs
        self.snapshot_timestamp = snapshot_timestamp
    
    def get_instance_networks_interfaces(self):
        """Get network info from a particular snapshot.
           Returns:
               A list of networks from a particular project
           Raises:
               MySQLError if a MySQL error occurs.
        I set the list  to get rid of duplicates 
        """
        instances = instance_dao.InstanceDao().get_instances(self.snapshot_timestamp)
        return list(set([self.parse_instance_network_instance(instance) for instance in instances]))

    def parse_instance_network_instance(self, instance_object):
        return ini.InstanceNetworkInterface(instance_object.network_interfaces)

    def _get_project_policies(self):
        """Get projects from data source.
        """
        project_policies = {}
        project_policies = (
            project_dao.ProjectDao().get_project_policies('projects',
                                                          self.\
                                                          snapshot_timestamp))
        return project_policies

    @staticmethod
    def _get_resource_count(project_policies, instance_network_interfaces):
        """Get resource count for org and project policies.

        Args:
            org_policies: organization policies from inventory.
            project_policies: project policies from inventory.
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.INSTANCE: len(instance_network_interfaces),
        }

        return resource_counts

    def run(self):
        """Runs the data collection."""
        enforced_networks_data = []
        project_policies = {}
        instance_network_interfaces = self.get_instance_networks_interfaces()
        enforced_networks_data.append(instance_network_interfaces)
        enforced_networks_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   instance_network_interfaces)

        return enforced_networks_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, enforced_networks_data, rules_engine):
        """Find violations in the policies.

        Args:
        #TODO: should enforced_network_data be a gce_instance 
            enforced_networks_data: enforced networks data to find violations in
            rules_engine: The rules engine to run.

        Returns:
            A list of violations
        """

        all_violations = []
        LOGGER.info('Finding enforced networks violations...')
        instance_network_interfaces = enforced_networks[0]
        print(enforced_networks[1])
        for instance_network_interface in instance_network_interfaces:
            LOGGER.debug('%s', instance_network_interface)
            violations = rules_engine.find_policy_violations(
                instance_network_interface)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

FAKE_global_configs = {
    'db_host': '127.0.0.1',
    'db_user': 'carlys',
    'db_name': 'forseti-carlys',
    'email_recipient': 'foo_email_recipient'
}
"""
print(FAKE_global_configs)
instance = InstanceNetworkInterfaceScanner(FAKE_global_configs, '20170615T173104Z')
enforced_networks, rcount = instance.run()
print(rcount)
RulesEngine = instance_network_interface_rules_engine.InstanceNetworkInterfaceRulesEngine('/Users/carly/Documents/forseti-security/tests/scanner/audit/data/instance_network_interface_test_rules_1.yaml')
violations = instance.find_violations(enforced_networks, RulesEngine)
for v in violations:
    print(str(v))
    """
