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

from google.cloud.security.common.data_access._db_connector import _DbConnector
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class OrganizationDao(_DbConnector):
    """Data access object (DAO) for Organizations."""

    def __init__(self):
        super(OrganizationDao, self).__init__()

    def get_org_iam_policies(self, timestamp):
        """Get the organization policies.

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
                    org = Organization(organization_id=row[0])
                    iam_policy = json.loads(row[1])
                    org_iam_policies[org] = iam_policy
                except ValueError:
                    LOGGER.warn('Error parsing json:\n %s', row[2])
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(MySQLError('organizations', e))
        return org_iam_policies
