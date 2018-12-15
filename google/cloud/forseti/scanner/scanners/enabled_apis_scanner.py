# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Scanner for Enabled APIs."""

import json

from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import enabled_apis_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class EnabledApisScanner(base_scanner.BaseScanner):
    """Scanner for enabled APIs."""

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
        super(EnabledApisScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = enabled_apis_rules_engine.EnabledApisRulesEngine(
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
            for api in violation.apis:
                violation_data = {
                    'full_name': violation.full_name,
                    'api_name': api,
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
            all_violations (list): A list of violations
        """
        all_violations = list(self._flatten_violations(all_violations))
        self._output_results_to_db(all_violations)

    def _find_violations(self, enabled_apis_data):
        """Find violations in the enabled APIs.

        Args:
            enabled_apis_data (list): enabled APIs data to find violations in.

        Returns:
            list: A list of all violations
        """
        all_violations = []
        LOGGER.info('Finding enabled API violations...')

        for project, enabled_apis in enabled_apis_data:
            violations = self.rules_engine.find_violations(
                project, enabled_apis)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: List of projects' enabled API data.

        Raises:
            NoDataError: If no enabled APIs are found.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            enabled_apis_data = []

            for apis in data_access.scanner_iter(session, 'enabled_apis'):
                enabled_apis = []
                for enabled_api in json.loads(apis.data):
                    if 'serviceName' in enabled_api:
                        enabled_apis.append(enabled_api['serviceName'])

                if enabled_apis:
                    enabled_apis_data.append(
                        (Project(apis.parent.name,
                                 apis.parent.full_name,
                                 apis.data),
                         enabled_apis))

        if not enabled_apis_data:
            LOGGER.warn('No Enabled APIs found. Exiting.')
            raise util_errors.NoDataError('No enabled APIs found. Exiting')

        return enabled_apis_data

    def run(self):
        """Runs the data collection."""
        try:
            enabled_apis_data = self._retrieve()
        except util_errors.NoDataError:
            return

        all_violations = self._find_violations(enabled_apis_data)
        self._output_results(all_violations)
