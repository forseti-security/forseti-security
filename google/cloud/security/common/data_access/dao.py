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

"""Provides the data access object (DAO)."""

from MySQLdb import DataError
from MySQLdb import IntegrityError
from MySQLdb import InternalError
from MySQLdb import NotSupportedError
from MySQLdb import OperationalError
from MySQLdb import ProgrammingError
from MySQLdb import cursors

from google.cloud.security.common.data_access._db_connector import _DbConnector
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import load_data_sql_provider
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.errors import NoResultsError
from google.cloud.security.common.data_access.sql_queries import create_tables
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.util.log_util import LogUtil


LOGGER = LogUtil.setup_logging(__name__)

CREATE_TABLE_MAP = {
    'org_iam_policies': create_tables.CREATE_ORG_IAM_POLICIES_TABLE,
    'projects': create_tables.CREATE_PROJECT_TABLE,
    'project_iam_policies': create_tables.CREATE_PROJECT_IAM_POLICIES_TABLE,
    # pylint: disable=line-too-long
    # TODO: Investigate improving so we can avoid the pylint disable.
    'raw_project_iam_policies': create_tables.CREATE_RAW_PROJECT_IAM_POLICIES_TABLE,
    'raw_org_iam_policies': create_tables.CREATE_RAW_ORG_IAM_POLICIES_TABLE,
}


class Dao(_DbConnector):
    """Data access object (DAO)."""

    def __init__(self):
        super(Dao, self).__init__()

    def _create_snapshot_table(self, resource_name, timestamp):
        """Creates a snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            snapshot_table_name: String of the created snapshot table.
        """
        snapshot_table_name = resource_name + '_' + timestamp
        create_table_sql = CREATE_TABLE_MAP[resource_name]
        create_snapshot_sql = create_table_sql.format(snapshot_table_name)
        cursor = self.conn.cursor()
        cursor.execute(create_snapshot_sql)
        return snapshot_table_name

    def load_data(self, resource_name, timestamp, data):
        """Load data into a snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
            data: An iterable or a list of data to be uploaded.

        Returns:
            None

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        try:
            snapshot_table_name = self._create_snapshot_table(
                resource_name, timestamp)
            csv_filename = csv_writer.write_csv(resource_name, data)
            load_data_sql = load_data_sql_provider.provide_load_data_sql(
                resource_name, csv_filename, snapshot_table_name)
            cursor = self.conn.cursor()
            cursor.execute(load_data_sql)
            self.conn.commit()
            # TODO: Return the snapshot table name so that it can be tracked
            # in the main snapshot table.
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def select_record_count(self, resource_name, timestamp):
        """Select the record count from a snapshot table.

        Args:
            resource_name: String of the resource name, which is embedded in
                the table name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
             Integer of the record count in a snapshot table.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        try:
            record_count_sql = select_data.RECORD_COUNT.format(
                resource_name, timestamp)
            cursor = self.conn.cursor()
            cursor.execute(record_count_sql)
            return cursor.fetchone()[0]
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def select_project_numbers(self, resource_name, timestamp):
        """Select the project numbers from a snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
             list of project numbers

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        try:
            project_numbers_sql = select_data.PROJECT_NUMBERS.format(timestamp)
            cursor = self.conn.cursor(cursorclass=cursors.DictCursor)
            cursor.execute(project_numbers_sql)
            rows = cursor.fetchall()
            return [row['project_number'] for row in rows]
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def execute_sql_with_fetch(self, resource_name, sql, values):
        """Executes a provided sql statement with fetch.

        Args:
            resource_name: String of the resource name.
            sql: String of the sql statement.
            values: Tuple of string for sql placeholder values.

        Returns:
             A list of tuples representing rows of sql query result.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        try:
            cursor = self.conn.cursor(cursorclass=cursors.DictCursor)
            cursor.execute(sql, values)
            return cursor.fetchall()
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def execute_sql_with_commit(self, resource_name, sql, values):
        """Executes a provided sql statement with commit.

        Args:
            resource_name: String of the resource name.
            sql: String of the sql statement.
            values: Tuple of string for sql placeholder values.

        Returns:
             None

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, values)
            self.conn.commit()
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    # pylint: disable=invalid-name
    # TODO: Investigate improving as to remove pylint disable.
    def select_latest_complete_snapshot_timestamp(self, statuses):
        """Select the latest timestamp of the completed snapshot.

        Args:
            statuses: The tuple of snapshot statuses to filter on.

        Returns:
             The string timestamp of the latest complete snapshot.

        Raises:
            MySQLError (NoResultsError) if no rows are found.
        """
        # Build a dynamic parameterized query string for filtering the
        # snapshot statuses
        if not statuses:
            statuses = ('SUCCESS')

        # TODO: Investigate improving to avoid the pylint disable.
        status_params = ','.join(
            ['%s' for s in statuses]) # pylint: disable=unused-variable
        filter_clause = ' where status in ({})'.format(status_params)
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                select_data.LATEST_SNAPSHOT_TIMESTAMP + filter_clause, statuses)
            rows = cursor.fetchall()
            if rows and rows[0]:
                return rows[0][0]
            raise NoResultsError('No snapshot cycle found.')
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError, NoResultsError) as e:
            raise MySQLError('snapshot_cycles', e)
