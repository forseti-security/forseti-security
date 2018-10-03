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

"""Scanner for the Lien rules engine."""

from google.cloud.forseti.common.gcp_type import bucket
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import location_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)


class LocationScanner(base_scanner.BaseScanner):
    """Scanner for Liens."""

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
        self.rules_engine = location_rules_engine.LocationRulesEngine(
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
            Dict[Resource, List[lien]]: mapping of a resource to the liens it
                contains.
        Raises:
            ValueError: if resources have an unexpected type.
        """
        resources = []

        resource_type_to_fn = {'bucket': bucket.Bucket.from_json}

        scoped_session, data_access = self.service_config.model_manager.get(
            self.model_name)
        with scoped_session as session:
            for resource_type, resource_fn in resource_type_to_fn.items():
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
                    resources.append(resource_fn(proj, resource.data))

        return resources

    def _find_violations(self, resources):
        """Find violations in liens.
        Args:
            parent_resource_to_liens (Dict[Resource, List[lien]]): mapping of
                a resource to the liens it contains.
        Returns:
            List[RuleViolation]: A list of all violations.
        """
        all_violations = []
        LOGGER.info('Finding lien violations...')

        for resource in resources:
            violations = self.rules_engine.find_violations(resource)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _output_results(self, all_violations):
        """Output results.
        Args:
            all_violations (List[RuleViolation]): A list of lien violations.
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
