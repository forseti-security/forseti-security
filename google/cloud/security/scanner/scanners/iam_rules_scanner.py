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
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.scanners import base_scanner


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,differing-param-doc,redundant-returns-doc


LOGGER = log_util.get_logger(__name__)


class IamPolicyScanner(base_scanner.BaseScanner):
    """Pipeline to IAM data from DAO"""

    def __init__(self, configs, snapshot_timestamp):
        """Constructor for the base pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as

        Returns:
            None
        """
        super(IamPolicyScanner, self).__init__(
            configs,
            snapshot_timestamp)
        self.snapshot_timestamp = snapshot_timestamp

    def _get_org_policies(self):
        """Get orgs from data source.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            The org policies.
        """
        org_policies = {}
        try:
            org_dao = organization_dao.OrganizationDao(self.configs)
            org_policies = org_dao.get_org_iam_policies(
                'organizations', self.snapshot_timestamp)
        except da_errors.MySQLError as e:
            LOGGER.error('Error getting Organization IAM policies: %s', e)
        return org_policies

    def _get_project_policies(self):
        """Get projects from data source.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            The project policies.
        """
        project_policies = {}
        project_policies = (
            project_dao.ProjectDao(self.configs)
                       .get_project_policies('projects',
                                             self.snapshot_timestamp))
        return project_policies

    def run(self):
        """Runs the data collection."""
        policy_data = []
        org_policies = self._get_org_policies()
        project_policies = self._get_project_policies()

        if not org_policies and not project_policies:
            LOGGER.warn('No policies found. Exiting.')
            sys.exit(1)
        resource_counts = self._get_resource_count(org_policies,
                                                   project_policies)
        policy_data.append(org_policies.iteritems())
        policy_data.append(project_policies.iteritems())

        return policy_data, resource_counts

    # pylint: disable=arguments-differ
    def find_violations(self, policies, rules_engine):
        """Find violations in the policies.

        Args:
            policies: The list of policies to find violations in.
            rules_engine: The rules engine to run.

        Returns:
            A list of violations
        """
        all_violations = []
        LOGGER.info('Finding policy violations...')
        for (resource, policy) in policies:
            LOGGER.debug('%s => %s', resource, policy)
            violations = rules_engine.find_policy_violations(
                resource, policy)
            LOGGER.debug(violations)
            all_violations.extend(violations)
        return all_violations

    @staticmethod
    def _get_resource_count(org_policies, project_policies):
        """Get resource count for org and project policies.

        Args:
            org_policies: organisation policies from inventory
            project_pollicies: project policies from inventory.
        Returns:
            Resource count map
        """
        resource_counts = {
            ResourceType.ORGANIZATION: len(org_policies),
            ResourceType.PROJECT: len(project_policies),
        }

        return resource_counts
