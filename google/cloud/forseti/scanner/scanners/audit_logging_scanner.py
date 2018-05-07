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

"""Scanner for Audit Logging."""

import json

from google.cloud.forseti.common.gcp_type import iam_policy
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import audit_logging_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.services import utils

LOGGER = logger.get_logger(__name__)


class AuditLoggingScanner(base_scanner.BaseScanner):
    """Scanner for Audit Logging."""

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
        super(AuditLoggingScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = audit_logging_rules_engine.AuditLoggingRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    @staticmethod
    def _flatten_violations(violations):
        """Flatten RuleViolations into a dict for each violation.

        Args:
            violations (list): The RuleViolations to flatten.

        Yields:
            dict: Iterator of RuleViolations as a dict per member.
        """
        for violation in violations:
            violation_data = {
                'full_name': violation.full_name,
                'service': violation.service,
                'log_type': violation.log_type,
            }
            if violation.unexpected_exemptions:
                violation_data['unexpected_exemptions'] = list(
                    violation.unexpected_exemptions)

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
            all_violations (list): A list of violations
        """
        all_violations = list(self._flatten_violations(all_violations))
        self._output_results_to_db(all_violations)

    def _find_violations(self, audit_logging_data):
        """Find violations in the audit log configs.

        Args:
            audit_logging_data (list): audit log data to find violations in.

        Returns:
            list: A list of all violations
        """
        all_violations = []
        LOGGER.info('Finding audit logging violations...')

        for project, audit_config in audit_logging_data:
            violations = self.rules_engine.find_violations(
                project, audit_config)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: List of projects' audit logging config data.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            project_configs = []
            ancestor_configs = {}
            # Types that can contain AuditConfigs in the IamPolicy.
            audit_policy_types = frozenset([
                'organization', 'folder', 'project'])

            for policy in data_access.scanner_iter(session, 'iam_policy'):
                if policy.parent.type not in audit_policy_types:
                    continue
                audit_config = iam_policy.IamAuditConfig.create_from(
                    json.loads(policy.data).get('auditConfigs', []))

                if policy.parent.type == 'project':
                    project_configs.append(
                        (Project(policy.parent.name,
                                 policy.parent.full_name,
                                 policy.data),
                         audit_config))
                elif audit_config.service_configs:
                    ancestor_configs[policy.parent.type, policy.parent.name] = (
                        audit_config)

        # Merge ancestor configs into project level configs.
        for project, audit_config in project_configs:
            ancestors = utils.get_resources_from_full_name(project.full_name)
            next(ancestors)
            for res_type, res_name in ancestors:
                ancestor_config = ancestor_configs.get((res_type, res_name))
                if ancestor_config:
                    audit_config.merge_configs(ancestor_config)

        return project_configs

    def run(self):
        """Runs the data collection."""
        audit_logging_data = self._retrieve()
        all_violations = self._find_violations(audit_logging_data)
        self._output_results(all_violations)
