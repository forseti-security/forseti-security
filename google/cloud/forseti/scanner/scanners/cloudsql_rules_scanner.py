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

"""Scanner for the CloudSQL acls rules engine."""

from google.cloud.forseti.common.gcp_type.cloudsql_access_controls import (
    CloudSqlAccessControl)
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import cloudsql_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)


class CloudSqlAclScanner(base_scanner.BaseScanner):
    """Scanner for CloudSQL acls."""

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
        super(CloudSqlAclScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = cloudsql_rules_engine.CloudSqlRulesEngine(
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
            violation_data = {'instance_name': violation.instance_name,
                              'full_name': violation.full_name,
                              'authorized_networks': (
                                  violation.authorized_networks),
                              'require_ssl': violation.require_ssl,
                              'project_id': violation.resource_id}
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
            all_violations (list): A list of violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_violations(self, cloudsql_acls):
        """Find violations in the policies.

        Args:
            cloudsql_acls (list): CloudSQL ACLs to find violations in

        Returns:
            list: A list of CloudSQL violations
        """
        all_violations = []
        LOGGER.info('Finding CloudSQL acl violations...')

        for cloudsql_acl in cloudsql_acls:
            violations = self.rules_engine.find_violations(
                cloudsql_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: CloudSQL ACL data.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            cloudsql_acls = []

            for instance in data_access.scanner_iter(session,
                                                     'cloudsqlinstance'):
                project_id = instance.parent.name
                cloudsql_acls.append(
                    CloudSqlAccessControl.from_json(
                        project_id=project_id,
                        full_name=instance.full_name,
                        instance_data=instance.data))

        return cloudsql_acls

    def run(self):
        """Runs the data collection."""
        cloudsql_acls = self._retrieve()
        all_violations = self._find_violations(cloudsql_acls)
        self._output_results(all_violations)
