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

"""Scanner for the Bucket acls rules engine."""

import json

from google.cloud.forseti.common.gcp_type.bucket_access_controls import (
    BucketAccessControls)
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.scanner.audit import buckets_rules_engine
from google.cloud.forseti.scanner.scanners import base_scanner


LOGGER = logger.get_logger(__name__)


class BucketsAclScanner(base_scanner.BaseScanner):
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
        super(BucketsAclScanner, self).__init__(
            global_configs,
            scanner_configs,
            service_config,
            model_name,
            snapshot_timestamp,
            rules)
        self.rules_engine = buckets_rules_engine.BucketsRulesEngine(
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
            violation_data = {'role': violation.role,
                              'entity': violation.entity,
                              'email': violation.email,
                              'domain': violation.domain,
                              'bucket': violation.bucket,
                              'full_name': violation.full_name,
                              'project_id': violation.project_id}
            yield {
                'full_name': violation.full_name,
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'resource_name': violation.resource_name,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data,
                'resource_data': violation.resource_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations
        """
        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(all_violations)

    def _find_violations(self, bucket_acls):
        """Find violations in the policies.

        Args:
            bucket_acls (list): Bucket ACLs to search for violations in.

        Returns:
            list: All violations.
        """
        all_violations = []
        LOGGER.info('Finding bucket acl violations...')

        for bucket_acl in bucket_acls:
            violations = self.rules_engine.find_violations(
                bucket_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    def _retrieve(self):
        """Retrieves the data for scanner.

        Returns:
            list: BigQuery ACL data
        """
        model_manager = self.service_config.model_manager
        scoped_session, data_access = model_manager.get(self.model_name)
        with scoped_session as session:
            bucket_acls = []

            for gcs_policy in data_access.scanner_iter(session, 'gcs_policy'):
                bucket = gcs_policy.parent
                project_id = bucket.parent.name
                acls = json.loads(gcs_policy.data)
                bucket_acls.extend(
                    BucketAccessControls.from_list(
                        project_id=project_id,
                        full_name=bucket.full_name,
                        acls=acls))

        return bucket_acls

    def run(self):
        """Run, he entry point for this scanner."""
        buckets_acls = self._retrieve()
        all_violations = self._find_violations(buckets_acls)
        self._output_results(all_violations)
