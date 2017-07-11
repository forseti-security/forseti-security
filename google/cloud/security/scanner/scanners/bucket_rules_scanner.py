# Copyright 2017 Google Inc.
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

import itertools

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import bucket_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.audit import buckets_rules_engine
from google.cloud.security.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class BucketsAclScanner(base_scanner.BaseScanner):
    """Pipeline to Bucket acls data from DAO"""
    def __init__(self, global_configs, scanner_configs, snapshot_timestamp,
                 rules):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            scanner_configs (dict): Scanner configurations.
            snapshot_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
            rules (str): Fully-qualified path and filename of the rules file.
        """
        super(BucketsAclScanner, self).__init__(
            global_configs,
            scanner_configs,
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
            violation_data = {}
            violation_data['role'] = violation.role
            violation_data['entity'] = violation.entity
            violation_data['email'] = violation.email
            violation_data['domain'] = violation.domain
            violation_data['bucket'] = violation.bucket
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }

    def _output_results(self, all_violations):
        """Output results.

        Args:
            all_violations (list): All violations
        """
        resource_name = 'violations'

        all_violations = self._flatten_violations(all_violations)
        self._output_results_to_db(resource_name, all_violations)

    # pylint: disable=arguments-differ
    def find_violations(self, bucket_data):
        """Find violations in the policies.

        Args:
            bucket_data (list): Buckets to find violations in

        Returns:
            list: All violations.
        """
        bucket_data = itertools.chain(*bucket_data)
        all_violations = []
        LOGGER.info('Finding bucket acl violations...')

        for (bucket, bucket_acl) in bucket_data:
            LOGGER.debug('%s => %s', bucket, bucket_acl)
            violations = self.rules_engine.find_policy_violations(
                bucket_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _get_resource_count(project_policies, buckets_acls):
        """Get resource count for org and project policies.

        Args:
            project_policies (list): project policies from inventory.
            buckets_acls (list): buclet acls from inventory.
        Returns:
            dict: Resource count map
        """
        resource_counts = {
            ResourceType.PROJECT: len(project_policies),
            ResourceType.BUCKETS_ACL: len(buckets_acls),
        }

        return resource_counts

    def _get_bucket_acls(self):
        """Get bucket acls from data source.

        Returns:
            list: List of bucket acls.
        """
        buckets_acls = {}
        buckets_acls = (bucket_dao
                        .BucketDao(self.global_configs)
                        .get_buckets_acls('buckets_acl',
                                          self.snapshot_timestamp))
        return buckets_acls

    def _retrieve(self):
        """Runs the data collection.

        Returns:
            list: Bucket ACL data.
        """
        buckets_acls_data = []
        project_policies = {}
        buckets_acls = self._get_bucket_acls()
        buckets_acls_data.append(buckets_acls.iteritems())
        buckets_acls_data.append(project_policies.iteritems())

        return buckets_acls_data

    def run(self):
        buckets_acls_data = self._retrieve()
        all_violations = self.find_violations(buckets_acls_data)
        self._output_results(all_violations)
