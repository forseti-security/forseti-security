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

import collections

from google.cloud.forseti.common.gcp_type.bigquery_access_controls import (
    BigqueryAccessControls)

from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import bigquery_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)

BigqueryAccessControlsData = collections.namedtuple(
    'BigqueryAccessControlsData',
    ['parent_project', 'bigquery_acl'])


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
            violation_data = {'dataset_id': violation.dataset_id,
                              'full_name': violation.full_name,
                              'access_domain': violation.domain,
                              'access_user_by_email': violation.user_email,
                              'access_special_group': violation.special_group,
                              'access_group_by_email': violation.group_email,
                              'role': violation.role, 'view': violation.view}
            yield {
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
            all_violations (list): A list of BigQuery violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_violations(self, bigquery_acl_data):
        """Find violations in the policies.

        Args:
            bigquery_acl_data (list): Big Query data to find violations in

        Returns:
            list: A list of BigQuery violations
        """
        all_violations = []
        LOGGER.info('Finding BigQuery acl violations...')

        for data in bigquery_acl_data:
            violations = self.rules_engine.find_policy_violations(
                data.parent_project, data.bigquery_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: BigQuery ACL data

        Raises:
            ValueError: if resources have an unexpected type.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            bq_acl_data = []

            for policy in data_access.scanner_iter(session, 'dataset_policy'):
                # dataset_policy are always in a dataset, which is always in a
                # project.
                dataset = policy.parent
                if dataset.type != 'dataset':
                    raise ValueError(
                        'Unexpected type of dataset_policy parent: '
                        'got %s, want dataset' % dataset.type
                    )

                if dataset.parent.type != 'project':
                    raise ValueError(
                        'Unexpected type of dataset_policy grandparent: '
                        'got %s, want project' % dataset.parent.type
                    )

                proj = project.Project(
                    project_id=dataset.parent.name,
                    full_name=dataset.parent.full_name,
                    data=policy.data,
                )
                # There is no functional use for project_id in this scanner,
                # other than to identify where the dataset comes from,
                # which can now be done with full_name.
                # In case you are tempted to get the project_id anyways,
                # do not use project_id = policy.parent.parent.name
                # which will cause db session conflict.
                # Instead, parse the project_id from the full_name.
                bq_acls = list(BigqueryAccessControls.from_json(
                    project_id=None,
                    dataset_id=dataset.name,
                    full_name=policy.full_name,
                    acls=policy.data))

                for bq_acl in bq_acls:
                    data = BigqueryAccessControlsData(
                        parent_project=proj,
                        bigquery_acl=bq_acl,
                    )
                    bq_acl_data.append(data)

            return bq_acl_data

    def run(self):
        """Runs the data collection."""
        bigquery_acl_data = self._retrieve()
        all_violations = self._find_violations(bigquery_acl_data)
        self._output_results(all_violations)
