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

"""Scanner for the Service Account Keys."""

from google.cloud.forseti.common.gcp_type.service_account import ServiceAccount
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import service_account_key_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class ServiceAccountKeyScanner(base_scanner.BaseScanner):
    """Check if ServiceAccount Keys have not been rotated."""

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
        super(ServiceAccountKeyScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)

        self.rules_engine = (
            service_account_key_rules_engine.ServiceAccountKeyRulesEngine(
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
            violation_data = {
                'project_id': violation.project_id,
                'service_account_name': violation.service_account_name,
                'service_account_id': violation.resource_id,
                'violation_reason': violation.violation_reason,
                'key_id': violation.key_id,
                'key_created_time': violation.key_created_time
            }
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'resource_name': violation.resource_name,
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
        all_violations = list(self._flatten_violations(all_violations))
        self._output_results_to_db(all_violations)

    def _find_violations(self, service_accounts):
        """Find violations in the policies.

        Args:
            service_accounts (list): ServiceAccounts to find violations in.

        Returns:
            list: All violations.
        """
        all_violations = []
        LOGGER.info('Finding service account key age violations...')

        for service_account in service_accounts:
            violations = self.rules_engine.find_violations(
                service_account)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Runs the data collection.

        Returns:
            list: ServiceAccount objects
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            service_accounts = []
            for service_account in data_access.scanner_iter(
                    session, 'serviceaccount'):
                project_id = service_account.parent.name
                service_accounts.append(
                    ServiceAccount.from_json(project_id,
                                             service_account.full_name,
                                             service_account.data,
                                             None))
            # Retrieve the service account key via a separate query because
            # session in the middle of yield_per() can not support simultaneous
            # queries.
            for service_account in service_accounts:
                position = (
                    service_account.full_name.find('serviceaccount'))
                service_acc_type_name = (
                    service_account.full_name[position:][:-1])

                keys = list(data_access.scanner_iter(
                    session, 'serviceaccount_key',
                    parent_type_name=service_acc_type_name))
                service_account.keys = ServiceAccount.parse_json_keys(keys)

        return service_accounts

    def run(self):
        """Run, the entry point for this scanner."""
        service_accounts = self._retrieve()
        all_violations = self._find_violations(service_accounts)
        self._output_results(all_violations)
