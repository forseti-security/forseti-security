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

import json

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class BucketDao(dao.Dao):
    """Data access object (DAO) for Organizations."""

    def __init__(self):
        super(BucketDao, self).__init__()

    def project_numbers_dao_stub(self, resource_name, timestamp):
        """Stub for selecting the project numbers for the orgsanisation.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            list of project numbers
        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        project_numbers_dao = project_dao.ProjectDao()
        project_numbers = project_numbers_dao.get_project_numbers(resource_name, timestamp)
        return project_numbers

    def get_buckets_by_project_number(self, resource_name, timestamp, project_number):
        """Select the buckets for project from a buckets snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            project_number: Project number

        Returns:
            list of project buckets

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        buckets_sql = select_data.BUCKETS_BY_PROJECT_ID.format(timestamp, project_number)
        rows = self.execute_sql_with_fetch(
            resource_name, buckets_sql, ())
        return [row['bucket_name'] for row in rows]
