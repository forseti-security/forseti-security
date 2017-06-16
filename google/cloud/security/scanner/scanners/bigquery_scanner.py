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

"""Scanner for the Big Query rules engine."""
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import bigquery_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner

LOGGER = log_util.get_logger(__name__)


class BigqueryScanner(base_scanner.BaseScanner):
    """Pipeline to Big Query acls data from DAO"""
    def __init__(self, snapshot_timestamp):
        """Initialization.

        Args:
            snapshot_timestamp: The snapshot timestamp
        """
        super(BigqueryScanner, self).__init__(
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

    def _get_bigquery_acls(self):
        """Get Big Query acls from data source.
        """
        bq_acls = {}
        bq_acls = bigquery_dao.BigqueryDao().\
                  get_bigquery_acls('bigquery_datasets',
                                    self.snapshot_timestamp)
        return bq_acls

    @staticmethod
    def _get_resource_count(project_policies, bigquery_acls):
        """Get resource count for org and project policies.

        Args:
            org_policies: organization policies from inventory.
            project_policies: project policies from inventory.
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.BIGQUERY_ACL: len(bigquery_acls),
        }

        return resource_counts

    def run(self):
        """Runs the data collection."""
        bigquery_acls_data = []
        project_policies = {}
        bigquery_acls = self._get_bigquery_acls()
        bigquery_acls_data.append(bigquery_acls.iteritems())
        bigquery_acls_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   bigquery_acls)

        return bigquery_acls_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, bigquery_data, rules_engine):
        """Find violations in the policies.

        Args:
            bigquery_data: Big Query data to find violations in
            rules_engine: The rules engine to run.

        Returns:
            A list of violations
        """

        all_violations = []
        LOGGER.info('Finding Big Query acl violations...')

        for (bigquery, bigquery_acl) in bigquery_data:
            LOGGER.debug('%s => %s', bigquery, bigquery_acl)
            violations = rules_engine.find_policy_violations(
                bigquery_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations
