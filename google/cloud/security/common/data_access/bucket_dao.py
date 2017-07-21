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

"""Provides the data access object (DAO) for buckets."""

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
from google.cloud.security.common.gcp_type import bucket_access_controls as bkt_acls
# pylint: enable=line-too-long
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class BucketDao(project_dao.ProjectDao):
    """Data access object (DAO) for Organizations."""

    def get_buckets_by_project_number(self, resource_name,
                                      timestamp, project_number):
        """Select the buckets for project from a buckets snapshot table.

        Args:
            resource_name (str): String of the resource name.
            timestamp (str): String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.
            project_number (int): Project number

        Returns:
            list: List of project buckets.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        # TODO: fix this not to use .format() for string-replacing
        # the project id.
        buckets_sql = select_data.BUCKETS_BY_PROJECT_ID.format(
            timestamp,
            project_number)
        rows = self.execute_sql_with_fetch(
            resource_name, buckets_sql, None)
        return [row['bucket_name'] for row in rows]

    def get_buckets_acls(self, resource_name, timestamp):
        """Select the bucket acls from a bucket acls snapshot table.

        Args:
            resource_name (str): String of the resource name.
            timestamp (str): String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            list: List of bucket acls.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        bucket_acls = {}
        cnt = 0
        try:
            bucket_acls_sql = select_data.BUCKET_ACLS.format(timestamp)
            rows = self.execute_sql_with_fetch(resource_name,
                                               bucket_acls_sql,
                                               None)
            for row in rows:
                bucket_acl = bkt_acls.\
                BucketAccessControls(bucket=row['bucket'],
                                     entity=row['entity'],
                                     email=row['email'],
                                     domain=row['domain'],
                                     role=row['role'],
                                     project_number=row['project_number'])
                bucket_acls[cnt] = bucket_acl
                cnt += 1
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            LOGGER.error(errors.MySQLError(resource_name, e))
        return bucket_acls

    def get_raw_buckets(self, resource_name, timestamp):
        """Select the bucket and its raw json.

        Args:
            resource_name (str): The resource type name.
            timestamp (str): The snapshot timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            list: List of dict mapping buckets to their raw json.
        """
        buckets_sql = select_data.RAW_BUCKETS.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource_name, buckets_sql, None)
        return rows
