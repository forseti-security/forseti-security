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

"""Scanner for the GroupsSettings rules engine."""

from google.cloud.forseti.common.gcp_type import groups_settings
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import groups_settings_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class GroupsSettingsScanner(base_scanner.BaseScanner):
    """Scanner for GroupsSettings data."""

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
        super(GroupsSettingsScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = groups_settings_rules_engine.GroupsSettingsRulesEngine(
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
            resource_data = {
                'whoCanAdd': violation.whoCanAdd,
                'whoCanJoin': violation.whoCanJoin,
                'whoCanViewMembership': violation.whoCanViewMembership,
                'whoCanViewGroup': violation.whoCanViewGroup,
                'whoCanInvite': violation.whoCanInvite,
                'allowExternalMembers': violation.allowExternalMembers,
                'whoCanLeaveGroup': violation.whoCanLeaveGroup,
            }

            yield {
                'resource_id': violation.group_email,
                'full_name': violation.group_email,
                'resource_name': violation.group_email,
                'resource_data': str(resource_data),
                'violation_data': violation.violation_reason,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations.
        """
        all_violations = list(self._flatten_violations(all_violations))
        self._output_results_to_db(all_violations)

    def _find_violations(self, settings_list):
        """Find violations in the policies.

        Args:
            settings_list (list): GroupsSettings list to find violations in.

        Returns:
            list: All violations.
        """
        all_violations = []
        LOGGER.info('Finding groups settings violations...')

        for settings in settings_list:
            violations = self.rules_engine.find_violations(settings)
            LOGGER.debug(violations)
            all_violations.extend(violations)

        return all_violations

    def _retrieve(self):
        """Runs the data collection.

        Returns:
            list: GroupsSettings objects.
        Raises:
            ValueError: if resources have an unexpected type.
        """
        settings_list = []

        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            for settings in data_access.scanner_fetch_groups_settings(session):
                email = settings[0].split('group/')[1]
                settings_list.append(groups_settings.GroupsSettings.from_json(email, settings[1]))

        return settings_list

    def run(self):
        """Run, the entry point for this scanner."""
        settings_list = self._retrieve()
        all_violations = self._find_violations(settings_list)
        self._output_results(all_violations)
