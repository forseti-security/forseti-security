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

"""Provides the data access object (DAO) for Organizations."""

import json

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class OrganizationDao(dao.Dao):
    """Data access object (DAO) for Organizations."""

    def get_organizations(self, resource_name, timestamp):
        """Get organizations from snapshot table.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
            A list of Organizations.
        """
        query = select_data.ORGANIZATIONS.format(timestamp)
        rows = self.execute_sql_with_fetch(resource_name, query, ())
        orgs = []
        for row in rows:
            org = organization.Organization(
                organization_id=row['org_id'],
                display_name=row['display_name'],
                lifecycle_state=row['lifecycle_state'])
            orgs.append(org)
        return orgs

    def get_organization(self, org_id, timestamp):
        """Get an organization from the database snapshot.

        Args:
            org_id: The Organization to retrieve.
            timestamp: The timestamp of the snapshot.

        Returns:
            An Organization from the database snapshot.

        Raises:
            MySQLError if there was an error getting the organization.
        """
        query = select_data.ORGANIZATION_BY_ID.format(timestamp)
        rows = self.execute_sql_with_fetch('organization', query, (org_id,))
        if rows:
            return organization.Organization(
                organization_id=rows[0]['org_id'],
                display_name=rows[0]['display_name'],
                lifecycle_state=rows[0]['lifecycle_state'])
        return None

    def get_org_iam_policies(self, resource_name, timestamp):
        """Get the organization policies.

        This does not raise any errors if there's a database or json parse
        error because we want to return as many organizations as possible.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
            A dict keyed by the organizations
            (gcp_type.organization.Organization) and their iam policies (dict).
        """
        org_iam_policies = {}
        query = select_data.ORG_IAM_POLICIES.format(timestamp)
        rows = self.execute_sql_with_fetch(resource_name, query, ())
        for row in rows:
            try:
                org = organization.Organization(
                    organization_id=row['org_id'])
                iam_policy = json.loads(row.get('iam_policy', {}))
                org_iam_policies[org] = iam_policy
            except ValueError:
                LOGGER.warn(
                    'Error parsing json:\n %s', row.get('iam_policy'))
        return org_iam_policies
