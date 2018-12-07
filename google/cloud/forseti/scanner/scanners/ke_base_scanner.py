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

"""KE Base scanner."""

import json

from google.cloud.forseti.common.gcp_type import ke_cluster
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.scanners.base_scanner import BaseScanner


LOGGER = logger.get_logger(__name__)


def ke_scanner_factory(scanner_name, rules_engine_cls):
    """Factory function for instantiating KeBaseScanner subclasses

    Args:
        scanner_name (str): a human-readable name for the subclass to
            fill in log messages.
        rules_engine_cls (BaseRulesEngine): a BaseRulesEngine subclass
            to implement the rules engine for the scanner subclass.

    Raises:
        TypeError: if rules_engine_cls isn't a BaseRulesEngine

    Returns:
        class: a subclass of KeBaseScanner.

    """
    if not issubclass(rules_engine_cls, bre.BaseRulesEngine):
        raise TypeError('rules_engine_cls must be derived from BaseRulesEngine')

    class KeBaseScanner(BaseScanner):
        """Common base class to implement KE scanners."""

        # some subclasses support additional violation fields.  This list
        # contains the names of these optional properties.  These
        # properties will be added to violations if they are found.
        _EXTRA_VIOLATION_FIELDS = ['node_pool_name']

        # subclasses should set this to a friendlyish name.  It's used to
        # fill in log messages.
        _SCANNER_NAME = scanner_name

        # subclasses should set this to the class that implements their
        # rule engine.
        _RULES_ENGINE_CLS = rules_engine_cls

        def __init__(self, global_configs, scanner_configs, service_config,
                     model_name, snapshot_timestamp, rules):
            """Initialization.

            Args:
                global_configs (dict): Global configurations.
                scanner_configs (dict): Scanner configurations.
                service_config (ServiceConfig): Forseti 2.0 service configs
                model_name (str): name of the data model
                snapshot_timestamp (str): Timestamp, formatted as
                    YYYYMMDDTHHMMSSZ.
                rules (str): Fully-qualified path and filename of the rules
                    file.

            Raises:
                NotImplementedError: subclasses must provide class variables
            """

            if type(self)._RULES_ENGINE_CLS is None:
                raise NotImplementedError(
                    'Only subclasses of KeBaseScanner can be instantiated'
                )

            super(KeBaseScanner, self).__init__(
                global_configs,
                scanner_configs,
                service_config,
                model_name,
                snapshot_timestamp,
                rules)

            self.rules_engine = type(self)._RULES_ENGINE_CLS(
                rules_file_path=self.rules,
                snapshot_timestamp=self.snapshot_timestamp,
            )
            self.rules_engine.build_rule_book(self.global_configs)

        def _flatten_violations(self, violations):
            """Flatten RuleViolations into a dict for each RuleViolation member.

            Args:
                violations (list): The RuleViolations to flatten.

            Yields:
                dict: Iterator of RuleViolations as a dict per member.
            """
            for violation in violations:
                violation_data = {
                    'violation_reason': violation.violation_reason,
                    'project_id': violation.project_id,
                    'cluster_name': violation.cluster_name,
                    'full_name': violation.full_name,
                }

                self._fill_extra_violation_data(violation, violation_data)

                yield {
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'resource_name': violation.resource_name,
                    'full_name': violation.full_name,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'violation_data': violation_data,
                    'resource_data': violation.resource_data,
                }

        def _fill_extra_violation_data(self, violation, violation_data):
            """Allow KE scanner subclasses to provide additional data.

            Args:
                violation (RuleViolation): the violation being processed.
                violation_data (dict): dict to be modified with the
                additional data.
            """
            for field in self._EXTRA_VIOLATION_FIELDS:
                if hasattr(violation, field):
                    violation_data[field] = getattr(violation, field)

        def _output_results(self, all_violations):
            """Output results.

            Args:
                all_violations (list): All violations
            """
            all_violations = list(self._flatten_violations(all_violations))
            self._output_results_to_db(all_violations)

        def _find_violations(self, ke_clusters):
            """Find violations in the policies.

            Args:
                ke_clusters (list): Clusters to find violations in.

            Returns:
                list: All violations.
            """
            all_violations = []
            LOGGER.info(
                'Finding ke cluster %s violations...',
                self._SCANNER_NAME,
            )

            for cluster in ke_clusters:
                violations = self.rules_engine.find_violations(
                    cluster)
                LOGGER.debug(violations)
                all_violations.extend(violations)
            return all_violations

        def _retrieve(self):
            """Runs the data collection.

            Returns:
                list: KE Cluster data.
            """
            model_manager = self.service_config.model_manager
            scoped_session, data_access = model_manager.get(self.model_name)
            with scoped_session as session:
                ke_clusters = []
                for cluster in data_access.scanner_iter(
                        session, 'kubernetes_cluster'):
                    proj = project.Project(
                        project_id=cluster.parent.name,
                        full_name=cluster.parent.full_name,
                    )
                    ke_clusters.append(
                        ke_cluster.KeCluster.from_json(proj, cluster.data))

            # Retrieve the service config via a separate query because session
            # in the middle of yield_per() can not support simultaneous queries.
            with scoped_session as session:
                for cluster in ke_clusters:
                    position = (
                        cluster.full_name.find('kubernetes_cluster')
                    )
                    ke_cluster_type_name = (
                        cluster.full_name[position:][:-1])

                    service_config = list(data_access.scanner_iter(
                        session, 'kubernetes_service_config',
                        parent_type_name=ke_cluster_type_name))[0]

                    cluster.server_config = json.loads(service_config.data)

            return ke_clusters

        def run(self):
            """Run, the entry point for this scanner."""
            ke_clusters = self._retrieve()
            all_violations = self._find_violations(ke_clusters)
            self._output_results(all_violations)

    return KeBaseScanner
