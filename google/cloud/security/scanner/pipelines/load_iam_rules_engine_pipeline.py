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

"""Pipeline for the IAM rules engine."""

from google.cloud.security.common.util import log_util
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.scanner.pipelines import base_data_pipeline

LOGGER = log_util.get_logger(__name__)


class LoadIamDataPipeline(base_data_pipeline.BaseDataPipeline):
    """Pipeline to IAM data from DAO"""

    def __init__(self, snapshot_timestamp):
        """Constructor for the base pipeline.

        Args:
            cycle_timestamp: String of timestamp, formatted as

        Returns:
            None
        """
        super(LoadIamDataPipeline, self).__init__(
            snapshot_timestamp)

    def _get_org_policies(self):
        """Get orgs from data source.

        Args:
            timestamp: The snapshot timestamp.

        Returns:
            The org policies.
        """
        org_policies = {}
        org_dao = organization_dao.OrganizationDao()
        org_policies = org_dao.get_org_iam_policies('organizations',
                                                    self.snapshot_timestamp)
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
            project_dao.ProjectDao().get_project_policies('projects',
                                                          self.snapshot_timestamp))
        return project_policies

    def _get_resource_count(self, org_policies, project_policies):
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

    def run(self):
        """Runs the data collection."""
        policy_data = []
        org_policies = self._get_org_policies()
        project_policies = self._get_project_policies()

        if not org_policies and not project_policies:
            LOGGER.warn('No policies found. Exiting.')
            sys.exit()
        resource_counts = self._get_resource_count(org_policies,
                                                   project_policies)
        policy_data.append(org_policies.iteritems())
        policy_data.append(project_policies.iteritems())

        return policy_data, resource_counts

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
