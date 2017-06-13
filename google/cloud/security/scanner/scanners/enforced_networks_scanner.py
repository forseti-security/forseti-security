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
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class EnforcedNetworksScanner(base_scanner.BaseScanner):
    """Pipeline to network enforcer from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(EnforcedNetworksScanner, self).__init__(
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

    def _get_networks_enforcer(self):
        """Get networks_enforcer from data source.
        """
        networks_enforcer = {}
        #TODP figure out what goes here
        networks_enforcer = networks_dao.NetworksDao().\
                        _get_networks_enforcer('enforced_networks_instances',
                                          self.snapshot_timestamp)

        return enforced_networks

    @staticmethod
    def _get_resource_count(project_policies, enforced_networks):
        """Get resource count for org and project policies.

        Args:
            org_policies: organization policies from inventory.
            project_policies: project policies from inventory.
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.NETWORKS_ENFORCER: len(enforced_networks),
        }

        return resource_counts

    def run(self):
        """Runs the data collection."""
        enforced_networks_data = []
        project_policies = {}
        enforced_networks = self._get_enforced_networks()
        enforced_networks_data.append(enforced_networks.iteritems())
        enforced_networks_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   enforced_networks)

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
        
        for (network, enforced_networks) in enforced_networks_data:
            LOGGER.debug('%s => %s', network, enforced_networks)
            violations = rules_engine.find_policy_violations(
                enforced_networks)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations
