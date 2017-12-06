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

"""Scanner for the Big Query rules engine."""

import itertools

from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.common.data_access import bigquery_dao
from google.cloud.forseti.common.gcp_type.resource import ResourceType
from google.cloud.forseti.scanner.audit import bigquery_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class BigqueryScanner(base_scanner.BaseScanner):
    """Scanner for BigQuery acls."""

    def __init__(self, global_configs, scanner_configs, service_config,
                 model_name, snapshot_timestamp,
                 rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            service_config (ServiceConfig): Forseti 2.0 service configs
            model_name (str): name of the data model
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(BigqueryScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = bigquery_rules_engine.BigqueryRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
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
            violation_data['dataset_id'] = violation.dataset_id
            violation_data['access_domain'] = violation.domain
            violation_data['access_user_by_email'] = violation.user_email
            violation_data['access_special_group'] = violation.special_group
            violation_data['access_group_by_email'] = violation.group_email
            violation_data['role'] = violation.role
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): A list of BigQuery violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_violations(self, bigquery_data):
        """Find violations in the policies.

        Args:
            bigquery_data (list): Big Query data to find violations in

        Returns:
            list: A list of BigQuery violations
        """
        bigquery_data = itertools.chain(*bigquery_data)

        all_violations = []
        LOGGER.info('Finding BigQuery acl violations...')

        for (bigquery, bigquery_acl) in bigquery_data:
            LOGGER.debug('%s => %s', bigquery, bigquery_acl)
            violations = self.rules_engine.find_policy_violations(
                bigquery_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _get_resource_count(project_policies, bigquery_acls):
        """Get resource count for org and project policies.

        Args:
            project_policies (list): project policies from inventory.
            bigquery_acls (list): BigQuery acls from inventory.

        Returns:
            dict: Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.BIGQUERY_ACL: len(bigquery_acls),
        }

        return resource_counts

    def _get_bigquery_acls(self):
        """Get Big Query acls from data source.

        Returns:
            list: List of Big Query acls.
        """
        bq_acls = {}
        bq_acls = (bigquery_dao
                   .BigqueryDao(self.global_configs)
                   .get_bigquery_acls('bigquery_datasets',
                                      self.snapshot_timestamp))
        return bq_acls

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: BigQuery ACL data
        """
        bigquery_acls_data = []
        project_policies = {}
        bigquery_acls = self._get_bigquery_acls()
        bigquery_acls_data.append(bigquery_acls.iteritems())
        bigquery_acls_data.append(project_policies.iteritems())

        return bigquery_acls_data

    def run(self):
        """Runs the data collection."""
        bigquery_acls_data = self._retrieve()
        all_violations = self._find_violations(bigquery_acls_data)
        self._output_results(all_violations)
