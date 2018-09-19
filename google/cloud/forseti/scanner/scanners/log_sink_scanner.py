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

"""Scanner for Log Sinks/Exports."""

import collections

from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.gcp_type.log_sink import LogSink
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import log_sink_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class LogSinkScanner(base_scanner.BaseScanner):
    """Scanner for Log Sinks/Exports."""

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
        super(LogSinkScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = log_sink_rules_engine.LogSinkRulesEngine(
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
                'sink_destination': violation.sink_destination,
                'sink_filter': violation.sink_filter,
                'sink_include_children': violation.sink_include_children,
            }

            yield {
                'resource_name': violation.resource_name,
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

    def _find_violations(self, log_sink_data):
        """Find violations in log sinks.

        Args:
            log_sink_data (list): log sink data to find violations in.

        Returns:
            list: A list of all violations
        """
        all_violations = []
        LOGGER.info('Finding log sink violations...')

        for parent_resource, log_sinks in log_sink_data:
            violations = self.rules_engine.find_violations(
                parent_resource, log_sinks)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: List of GCP resources' log sinks.
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            log_sink_data = []

            sinks = collections.defaultdict(list)
            for sink in data_access.scanner_iter(session, 'sink'):
                sinks[sink.parent_type_name].append(LogSink.from_json(
                    sink.parent, sink.data))

            # Create a list (possibly empty) of sinks for each parent resource.
            for parent_type in ['organization', 'billing_account', 'folder',
                                'project']:
                for parent in data_access.scanner_iter(session, parent_type):
                    parent_resource = resource_util.create_resource(
                        resource_id=parent.name,
                        resource_type=parent_type,
                        full_name=parent.full_name)
                    log_sink_data.append((parent_resource,
                                          sinks.get(parent.type_name, [])))

        return log_sink_data

    def run(self):
        """Runs the data collection."""
        log_sink_data = self._retrieve()
        all_violations = self._find_violations(log_sink_data)
        self._output_results(all_violations)
