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
from google.cloud.security.common.data_access import networks_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.audit import gce_networking_rules_engine
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class GceFirewallNetworksScanner(base_scanner.BaseScanner):
    """Pipeline to network enforcer from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(GceFirewallNetworksScanner, self).__init__(
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_project_policies(self):
        """Get projects from data source.
        """
        project_policies = {}
        project_policies = (
            project_dao.ProjectDao().get_project_policies('projects',
                                                          self.\
                                                          snapshot_timestamp))
        return project_policies

    def _get_gce_instances(self):
        """Get GCE networks from data source.
        """
        gce_networks = {}
        gce_networks = networks_dao.NetworksDao().\
                        get_networks(self.snapshot_timestamp)

        return gce_networks

    @staticmethod
    def _get_resource_count(project_policies, gce_instances):
        """Get resource count for org and project policies.

        Args:
            org_policies: organization policies from inventory.
            project_policies: project policies from inventory.
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.GCE_NETWORK: len(gce_instances),
        }

        return resource_counts

    def run(self):
        """Runs the data collection."""
        enforced_networks_data = []
        project_policies = {}
        gce_instances = self._get_gce_instances()
        enforced_networks_data.append(gce_instances)
        enforced_networks_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   gce_instances)

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
        
        for enforced_networks in enforced_networks_data:
            LOGGER.debug('%s', enforced_networks)
            violations = rules_engine.find_policy_violations(
                enforced_networks)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

def main():
    print("hi")
    g = GceFirewallNetworksScanner('20170615T173104Z')
    enforced_networks_data, resource_counts = g.run()
    rules_engine = gce_networking_rules_engine.GceNetworksRulesEngine('/Users/carly/Documents/forseti-security/temp.rules')
    violations = g.find_violations(enforced_networks_data, rules_engine)
    print(violations)



main()
