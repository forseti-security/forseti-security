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
from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import bucket_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class BucketsAclScanner(base_scanner.BaseScanner):
    """Pipeline to Bucket acls data from DAO"""
    def __init__(self, global_configs, snapshot_timestamp):
        """Initialization.

        Args:
            global_configs (dict): Global configurations.
            snapshot_timestamp (str): The snapshot timestamp
        """
        super(BucketsAclScanner, self).__init__(
            global_configs,
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_project_policies(self):
        """Get projects from data source.

        Returns:
            dict: If successful returns a dictionary of project policies
        """
        project_policies = {}
        project_policies = (project_dao
                            .ProjectDao(self.global_configs)
                            .get_project_policies('projects',
                                                  self.snapshot_timestamp))
        return project_policies

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

    def run(self):
        """Runs the data collection.

        Returns:
            tuple: Returns a tuple of lists. The first one is a list of
                bucket ACL data. The second one is a dictionary of resource
                counts
        """
        buckets_acls_data = []
        project_policies = {}
        buckets_acls = self._get_bucket_acls()
        buckets_acls_data.append(buckets_acls.iteritems())
        buckets_acls_data.append(project_policies.iteritems())

        resource_counts = self._get_resource_count(project_policies,
                                                   buckets_acls)

        return buckets_acls_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, bucket_data, rules_engine):
        """Find violations in the policies.

        Args:
            bucket_data (list): Buckets to find violations in
            rules_engine (BucketRulesEngine): The rules engine to run.

        Returns:
            list: A list of bucket violations
        """

        all_violations = []
        LOGGER.info('Finding bucket acl violations...')

        for (bucket, bucket_acl) in bucket_data:
            LOGGER.debug('%s => %s', bucket, bucket_acl)
            violations = rules_engine.find_policy_violations(
                bucket_acl)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations
