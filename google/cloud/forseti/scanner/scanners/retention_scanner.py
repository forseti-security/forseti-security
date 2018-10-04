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

"""Scanner for the Bucket retention rules engine."""

import json

from google.cloud.forseti.common.gcp_type.bucket_access_controls import (
    BucketAccessControls)
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import retention_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.common.gcp_type import retention_bucket


LOGGER = logger.get_logger(__name__)


class RetentionScanner(base_scanner.BaseScanner):
    """Pipeline to Bucket acls data from DAO."""

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
        super(RetentionScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = retention_rules_engine.RetentionRulesEngine(
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

        """
            rttRuleViolation = namedtuple(
        'RuleViolation',
        ['resource_name', 'resource_type', 'full_name', 'rule_name', 'rule_index',
         'violation_type', 'violation_describe'])
        """
        for violation in violations:
            violation_data = {'describe': violation.violation_describe}

            yield {
                'resource_name': violation.resource_name,
                'resource_type': violation.resource_type,
                'full_name': violation.full_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'resource_data': "",
                'resource_id': ""
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_bucket_violations(self, bucket_lifecycle_info):
        """Find violations in the policies.

        Args:
            bucket_lifecycle_info (list (RetentionBucket)): Bucket lifecycle to search for violations in.

        Returns:
            list: All violations.
        """
        all_violations = []
        LOGGER.info('Finding retention violations...')

        for single_info in bucket_lifecycle_info:
            violations = self.rules_engine.find_buckets_violations(
                single_info)
            all_violations.extend(violations)

        return all_violations

    def _retrieve_bucket(self):
        """Retrieves the bucket data for scanner.

        Returns:
            list: the data column of bucket rows
        """

        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        all_lifecycle_info = []
        with scoped_session as session:
            i = 0
            for bucketinfo in data_access.scanner_iter(session, 'bucket'):
                lifecycle_info = retention_bucket.RetentionBucket.from_json(bucketinfo)
                all_lifecycle_info.append(lifecycle_info)

        return all_lifecycle_info

    def run(self):
        """Run, he entry point for this scanner."""
        all_lifecycle_info = self._retrieve_bucket()
        all_violations = self._find_bucket_violations(all_lifecycle_info)
        self._output_results(all_violations)