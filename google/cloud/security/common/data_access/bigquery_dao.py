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

"""Provides the data access object (DAO) for Big Query."""

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access.sql_queries import select_data
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type import bigquery_access_controls as bq_acls
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class BigqueryDao(project_dao.ProjectDao):
    """Data access object (DAO) for Organizations."""

    def get_bigquery_acls(self, resource_name, timestamp):
        """Select the Big Query acls from a Big Query acls snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            List of Big Query acls.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        bigquery_acls = {}
        cnt = 0
        try:
            bigquery_acls_sql = select_data.BIGQUERY_ACLS.format(timestamp)
            rows = self.execute_sql_with_fetch(resource_name,
                                               bigquery_acls_sql,
                                               None)
            for row in rows:
                bigquery_acl = bq_acls.\
                BigqueryAccessControls(dataset_id=row['dataset_id'],
                                       special_group=\
                                       row['access_special_group'],
                                       user_email=row['access_user_by_email'],
                                       domain=row['access_domain'],
                                       role=row['role'],
                                       group_email=\
                                       row['access_group_by_email'],
                                       project_id=row['project_id'])
                bigquery_acls[cnt] = bigquery_acl
                cnt += 1
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(errors.MySQLError(resource_name, e))
        return bigquery_acls
