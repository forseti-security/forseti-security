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

"""Scanner for the IAM rules engine."""
import sys

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import errors as da_errors
from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner


LOGGER = log_util.get_logger(__name__)


class IamPolicyScanner(base_scanner.BaseScanner):
    """Pipeline to IAM data from DAO"""

    def __init__(self, global_configs, snapshot_timestamp):
        """Constructor for the base pipeline.

        Args:
            global_configs (dict): Global configurations.
            cycle_timestamp (str): String of timestamp, formatted as
        """
        super(IamPolicyScanner, self).__init__(
            global_configs,
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_org_iam_policies(self):
        """Get orgs IAM policies from data source.

        Args:
            timestamp (str): The snapshot timestamp.

        Returns:
            dict: The org policies.
        """
        org_policies = {}
        try:
            org_dao = organization_dao.OrganizationDao(self.global_configs)
            org_policies = org_dao.get_org_iam_policies(
                'organizations', self.snapshot_timestamp)
        except da_errors.MySQLError as e:
            LOGGER.error('Error getting Organization IAM policies: %s', e)
        return org_policies

    def _get_folder_iam_policies(self):
        """Get folder IAM policies from data source.

        Args:
            timestamp (str): The snapshot timestamp.

        Returns:
            dict: The folder policies.
        """
        folder_policies = {}
        try:
            fdao = folder_dao.FolderDao(self.global_configs)
            folder_policies = fdao.get_folder_iam_policies(
                'folders', self.snapshot_timestamp)
        except da_errors.MySQLError as e:
            LOGGER.error('Error getting Folder IAM policies: %s', e)
        return folder_policies

    def _get_project_iam_policies(self):
        """Get project IAM policies from data source.

        Args:
            timestamp (str): The snapshot timestamp.

        Returns:
            dict: The project policies.
        """
        project_policies = {}
        project_policies = (project_dao
                            .ProjectDao(self.global_configs)
                            .get_project_policies('projects',
                                                  self.snapshot_timestamp))
        return project_policies

    def run(self):
        """Runs the data collection."""
        policy_data = []
        org_policies = self._get_org_iam_policies()
        folder_policies = self._get_folder_iam_policies()
        project_policies = self._get_project_iam_policies()

        if not any([org_policies, folder_policies, project_policies]):
            LOGGER.warn('No policies found. Exiting.')
            sys.exit(1)
        resource_counts = self._get_resource_count(
            org_iam_policies=org_policies,
            folder_iam_policies=folder_policies,
            project_iam_policies=project_policies)
        policy_data.append(org_policies.iteritems())
        policy_data.append(folder_policies.iteritems())
        policy_data.append(project_policies.iteritems())

        return policy_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, policies, rules_engine):
        """Find violations in the policies.

        Args:
            policies (list): The policies to find violations in.
            rules_engine (RuleEngine): The rules engine to run.

        Returns:
            list: A list of violations.
        """
        all_violations = []
        LOGGER.info('Finding policy violations...')
        for (resource, policy) in policies:
            LOGGER.debug('%s => %s', resource, policy)
            violations = rules_engine.find_policy_violations(
                resource, policy)
            all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _get_resource_count(**kwargs):
        """Get resource count for IAM policies.

        Args:
            kwargs: The policies to get resource counts for.

        Returns:
            dict: Resource count map.
        """
        resource_counts = {
            ResourceType.ORGANIZATION: len(kwargs.get('org_iam_policies', [])),
            ResourceType.FOLDER: len(kwargs.get('folder_iam_policies', [])),
            ResourceType.PROJECT: len(kwargs.get('project_iam_policies', [])),
        }

        return resource_counts
