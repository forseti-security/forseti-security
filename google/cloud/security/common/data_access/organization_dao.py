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

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.errors import MySQLError
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

        Raise:
            MySQLError if there's an error fetching the organizations.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(select_data.ORGANIZATIONS.format(timestamp))
            rows = cursor.fetchall()
            orgs = []
            for row in rows:
                org = organization.Organization(
                    organization_id=row[0],
                    display_name=row[2],
                    lifecycle_state=row[3])
                orgs.append(org)
            return orgs
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def get_organization(self, timestamp, org_id):
        """Get an organization from the database snapshot.

        Args:
            timestamp: The timestamp of the snapshot.
            org_id: The Organization to retrieve.

        Returns:
            An Organization from the database snapshot.

        Raises:
            MySQLError if there was an error getting the organization.
        """
        try:
            cursor = self.conn.cursor()
            query = select_data.ORGANIZATION_BY_ID.format(timestamp)
            cursor.execute(query, org_id)
            row = cursor.fetchone()
            org = organization.Organization(
                organization_id=row[0],
                display_name=row[2],
                lifecycle_state=row[3])
            return org
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(org_id, e)

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
        try:
            cursor = self.conn.cursor()
            cursor.execute(select_data.ORG_IAM_POLICIES.format(timestamp))
            rows = cursor.fetchall()
            for row in rows:
                try:
                    org = organization.Organization(organization_id=row[0])
                    iam_policy = json.loads(row[1])
                    org_iam_policies[org] = iam_policy
                except ValueError:
                    LOGGER.warn('Error parsing json:\n %s', row[1])
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(MySQLError(resource_name, e))
        return org_iam_policies
