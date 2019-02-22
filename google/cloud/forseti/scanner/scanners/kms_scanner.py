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

"""Scanner for the KMS rules engine."""

from google.cloud.forseti.common.gcp_type import crypto_key
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import kms_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner

LOGGER = logger.get_logger(__name__)


class KMSScanner(base_scanner.BaseScanner):
    """Scanner for CryptoKeys data."""

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
        super(KMSScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = kms_rules_engine.KMSRulesEngine(
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
            violation_data = {'resource_id': violation.resource_id,
                              'full_name': violation.full_name,
                              'rotation_period': violation.rotation_period,
                              'state': violation.state,
                              'protection_level': violation.protection_level,
                              'algorithm': violation.algorithm,
                              'purpose': violation.purpose}
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'resource_name': violation.resource_id,
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
            all_violations (list): All violations.
        """
        all_violations = list(self._flatten_violations(all_violations))
        self._output_results_to_db(all_violations)

    def _find_violations(self, keys):
        """Find violations in the policies.

        Args:
            keys (list): CryptoKeys to find violations in.

        Returns:
            list: All violations.
        """
        all_violations = []
        LOGGER.info('Finding crypto key rotation violations...')

        for key in keys:
            violations = self.rules_engine.find_violations(key)
            LOGGER.debug(violations)
            all_violations.extend(violations)

        return all_violations

    def _retrieve(self):
        """Runs the data collection.

        Returns:
            list: CryptoKey objects.
        Raises:
            ValueError: if resources have an unexpected type.
        """
        keys = []

        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            for key in data_access.scanner_iter(session, 'kms_cryptokey'):
                if not key.parent_type_name.startswith('kms_keyring'):
                    raise ValueError(
                        'Unexpected type of parent resource type: '
                        'got %s, want kms_keyring' % key.parent_type_name
                    )

                keys.append(crypto_key.CryptoKey.from_json(
                    key.name,
                    key.full_name,
                    key.parent_type_name,
                    key.type,
                    key.data))

        return keys

    def run(self):
        """Run, the entry point for this scanner."""
        keys = self._retrieve()
        all_violations = self._find_violations(keys)
        self._output_results(all_violations)
