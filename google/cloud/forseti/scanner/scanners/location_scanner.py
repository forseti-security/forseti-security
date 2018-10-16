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

"""Scanner for the resource location rules engine."""


from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource_util
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import location_rules_engine as lre
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)


class LocationScanner(base_scanner.BaseScanner):
    """Scanner for resource locations."""

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
        super(LocationScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = lre.LocationRulesEngine(
            rules_file_path=self.rules,
            snapshot_timestamp=self.snapshot_timestamp)
        self.rules_engine.build_rule_book(self.global_configs)

    def run(self):
        """Runs the data collection."""
        resources = self._retrieve()
        all_violations = self._find_violations(resources)
        self._output_results(all_violations)

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            List[Resource]: resources to check for violations.
        Raises:
            ValueError: if resources have an unexpected type.
        """
        resources = []

        scoped_session, data_access = self.service_config.model_manager.get(
            self.model_name)
        with scoped_session as session:
            for resource_type in lre.SUPPORTED_LOCATION_RESOURCE_TYPES:
                for resource in data_access.scanner_iter(
                        session, resource_type):

                    if resource.parent.type != 'project':
                        raise ValueError(
                            'Unexpected type of parent resource type: '
                            'got %s, want project' % resource.parent.type
                        )

                    proj = project.Project(
                        project_id=resource.parent.name,
                        full_name=resource.parent.full_name,
                    )
                    resources.append(resource_util.create_resource_from_json(
                        resource_type, proj, resource.data))

        return resources

    def _find_violations(self, resources):
        """Find location violations in the given resources.

        Args:
            resources (List[resource]): resources to check for violations in.

        Returns:
            List[RuleViolation]: A list of all violations.
        """
        all_violations = []
        LOGGER.info('Finding resource locations violations...')

        for resource in resources:
            violations = self.rules_engine.find_violations(resource)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (List[RuleViolation]): A list of resource location
                violations.
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    @staticmethod
    def _flatten_violations(violations):
        """Flatten violations into a dict.

        Args:
            violations (List[RuleViolation]): The violations to flatten.

        Yields:
            Iterator[dict]: flattened violations for each violation.
        """
        for violation in violations:
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation.violation_data,
                'resource_data': violation.resource_data
            }
