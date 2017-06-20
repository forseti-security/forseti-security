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

"""Scanner for the CloudSQL acls rules engine."""
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import cloudsql_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class CloudSqlAclScanner(base_scanner.BaseScanner):
    """Pipeline to CloudSQL acls data from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp (str): The snapshot timestamp
        """
        super(CloudSqlAclScanner, self).__init__(
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_project_policies(self):
        """Get projects from data source.

        Returns:
            dict: If successful returns a dictionary of project policies
        """
        project_policies = {}
        project_policies = (
            project_dao.ProjectDao().get_project_policies('projects',
                                                          self.\
                                                          snapshot_timestamp))
        return project_policies

    def _get_cloudsql_acls(self):
        """Get CloudSQL acls from data source.

        Returns:
            list: List of CloudSql acls.
        """
        cloudsql_acls = {}
        cloudsql_acls = cloudsql_dao.CloudsqlDao().\
                        get_cloudsql_acls('cloudsql_instances',
                                          self.snapshot_timestamp)

        return cloudsql_acls

    @staticmethod
    def _get_resource_count(project_policies, cloudsql_acls):
        """Get resource count for org and project policies.

        Args:
            org_policies (list): organization policies from inventory.
            project_policies (list): project policies from inventory.
        Returns:
            dict: Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.CLOUDSQL_ACL: len(cloudsql_acls),
        }

        return resource_counts

    def run(self):
        """Runs the data collection.

        Returns:
            tuple: Returns a tuple of lists. The first one is a list of
                CloudSql ACL data. The second one is a dictionary of resource
                counts
        """
        cloudsql_acls_data = []
        project_policies = {}
        cloudsql_acls = self._get_cloudsql_acls()
        cloudsql_acls_data.append(cloudsql_acls.iteritems())
        cloudsql_acls_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   cloudsql_acls)

        return cloudsql_acls_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, cloudsql_data, rules_engine):
        """Find violations in the policies.

        Args:
            cloudsql_data (list): CloudSQL data to find violations in
            rules_engine (:obj:`CloudsqlRulesEngine`): The rules engine to run.

        Returns:
            list: A list of CloudSQL violations
        """

        all_violations = []
        LOGGER.info('Finding CloudSQL acl violations...')

        for (cloudsql, cloudsql_acl) in cloudsql_data:
            LOGGER.debug('%s => %s', cloudsql, cloudsql_acl)
            violations = rules_engine.find_policy_violations(
                cloudsql_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations
