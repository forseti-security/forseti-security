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

import itertools

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import cloudsql_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.audit import cloudsql_rules_engine
from google.cloud.security.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class CloudSqlAclScanner(base_scanner.BaseScanner):
    """Pipeline to CloudSQL acls data from DAO"""
    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            snapshot_timestamp (str): The snapshot timestamp
        """
        super(CloudSqlAclScanner, self).__init__(
            global_configs,
            scanner_configs,
            snapshot_timestamp,
            rules)
        self.rules_engine = cloudsql_rules_engine.CloudSqlRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    def _flatten_violations(self, violations):
        for violation in violations:
            violation_data = {}
            violation_data['instance_name'] = violation.instance_name
            violation_data['authorized_networks'] =\
                                                  violation.authorized_networks
            violation_data['ssl_enabled'] = violation.ssl_enabled
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }

    def _output_results(self, all_violations, resource_counts):
        resource_name = 'violations'

        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(resource_name, all_violations)

    # pylint: disable=arguments-differ
    def find_violations(self, cloudsql_data):
        """Find violations in the policies.

        Args:
            cloudsql_data (list): CloudSQL data to find violations in
            rules_engine (CloudsqlRulesEngine): The rules engine to run.

        Returns:
            list: A list of CloudSQL violations
        """
        cloudsql_data = itertools.chain(*cloudsql_data)

        all_violations = []
        LOGGER.info('Finding CloudSQL acl violations...')

        for (cloudsql, cloudsql_acl) in cloudsql_data:
            LOGGER.debug('%s => %s', cloudsql, cloudsql_acl)
            violations = self.rules_engine.find_policy_violations(
                cloudsql_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _get_resource_count(project_policies, cloudsql_acls):
        """Get resource count for org and project policies.

        Args:
            project_policies (list): project_policies policies from inventory.
            cloudsql_acls (list): CloudSql ACLs from inventory.
        Returns:
            dict: Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.CLOUDSQL_ACL: len(cloudsql_acls),
        }

        return resource_counts

    def _get_cloudsql_acls(self):
        """Get CloudSQL acls from data source.

        Returns:
            list: List of CloudSql acls.
        """
        cloudsql_acls = {}
        cloudsql_acls = (cloudsql_dao
                         .CloudsqlDao(self.global_configs)
                         .get_cloudsql_acls('cloudsql_instances',
                                            self.snapshot_timestamp))

        return cloudsql_acls

    def _retrieve(self):
        cloudsql_acls_data = []
        project_policies = {}
        cloudsql_acls = self._get_cloudsql_acls()
        cloudsql_acls_data.append(cloudsql_acls.iteritems())
        cloudsql_acls_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   cloudsql_acls)

        return cloudsql_acls_data, resource_counts

    def run(self):
        """Runs the data collection.

        Returns:
            tuple: Returns a tuple of lists. The first one is a list of
                CloudSql ACL data. The second one is a dictionary of resource
                counts
        """
        cloudsql_acls_data, resource_counts = self._retrieve()
        all_violations = self.find_violations(cloudsql_acls_data)
        self._output_results(all_violations, resource_counts)
