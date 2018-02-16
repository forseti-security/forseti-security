# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

from google.cloud.forseti.common.data_access import _db_connector
from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.data_access import load_data_sql_provider
from google.cloud.forseti.common.data_access.errors import MySQLError
from google.cloud.forseti.common.data_access.errors import NoResultsError
from google.cloud.forseti.common.data_access.sql_queries import select_data
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)

SNAPSHOT_STATUS_FILTER_CLAUSE = ' where status in ({})'


class Dao(_db_connector.DbConnector):
    """Data access object (DAO)."""

    @staticmethod
    def map_row_to_object(object_class, row):
        """Instantiate an object from database row.

        TODO: Make this go away when we start using an ORM.

        Args:
            object_class (object): The object class to create.
            row (row): The database row to map.

        Returns:
            obj_class: A new "obj_class", created from the row.
        """
        return object_class(**row)

    @staticmethod
    def _create_snapshot_table_name(resource_name, timestamp):
        """Create the snapshot table if it doesn't exist.

        Args:
            resource_name (str): String of the resource name.
            timestamp (str): String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            str: String of the created snapshot table name.
        """
        return resource_name + '_' + timestamp

    def load_data(self, resource_name, timestamp, data):
        """Load data into a snapshot table.

        Args:
            resource_name (str): String of the resource name.
            timestamp (str): String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.
            data (iterable): An iterable or a list of data to be uploaded.

        Raises:
            MySQLError: When an error has occured while executing the query.
        """
        with csv_writer.write_csv(resource_name, data) as csv_file:
            try:
                snapshot_table_name = self._create_snapshot_table_name(
                    resource_name, timestamp)
                load_data_sql = load_data_sql_provider.provide_load_data_sql(
                    resource_name, csv_file.name, snapshot_table_name)
                LOGGER.debug('SQL: %s', load_data_sql)
                cursor = self.conn.cursor()
                cursor.execute(load_data_sql)
                self.conn.commit()
                # TODO: Return the snapshot table name so that it can be tracked
                # in the main snapshot table.
            except (DataError, IntegrityError, InternalError,
                    NotSupportedError, OperationalError,
                    ProgrammingError) as e:
                raise MySQLError(resource_name, e)

    def select_record_count(self, resource_name, timestamp):
        """Select the record count from a snapshot table.

        Args:
            resource_name (str): String of the resource name, which is
                embedded in the table name.
            timestamp (str): String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            int: Integer of the record count in a snapshot table.

        Raises:
            MySQLError: When an error has occured while executing the query.
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

    def select_group_ids(self, resource_name, timestamp):
        """Select the group ids from a snapshot table.

        Args:
            resource_name (str): String of the resource name.
            timestamp (str): String of timestamp, formatted as
                YYYYMMDDTHHMMSSZ.

        Returns:
            list: A list of group ids.

        Raises:
            MySQLError: When an error has occured while executing the query.
        """
        try:
            group_ids_sql = select_data.GROUP_IDS.format(timestamp)
            cursor = self.conn.cursor(cursorclass=cursors.DictCursor)
            cursor.execute(group_ids_sql)
            rows = cursor.fetchall()
            return [row['group_id'] for row in rows]
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def execute_sql_with_fetch(self, resource_name, sql, values):
        """Executes a provided sql statement with fetch.

        Args:
            resource_name (str): String of the resource name.
            sql (str): String of the sql statement.
            values (tuple): Tuple of string for sql placeholder values.

        Returns:
            list: A list of dict representing rows of sql query result.

        Raises:
            MySQLError: When an error has occured while executing the query.
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
            resource_name (str): String of the resource name.
            sql (str): String of the sql statement.
            values (tuple): Tuple of string for sql placeholder values.

        Raises:
            MySQLError: When an error has occured while executing the query.
        """
        try:
            cursor = self.conn.cursor()
            cursor.execute(sql, values)
            self.conn.commit()
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError) as e:
            raise MySQLError(resource_name, e)

    def get_latest_snapshot_timestamp(self, statuses):
        """Select the latest timestamp of the completed snapshot.

        Args:
            statuses (tuple): The tuple of snapshot statuses to filter on.

        Returns:
            str: The string timestamp of the latest complete snapshot.

        Raises:
            MySQLError: When no rows are found.
        """
        # Build a dynamic parameterized query string for filtering the
        # snapshot statuses
        if not isinstance(statuses, tuple):
            statuses = ('SUCCESS',)

        status_params = ','.join(['%s']*len(statuses))
        filter_clause = SNAPSHOT_STATUS_FILTER_CLAUSE.format(status_params)
        try:
            cursor = self.conn.cursor()
            cursor.execute(
                select_data.LATEST_SNAPSHOT_TIMESTAMP + filter_clause, statuses)
            row = cursor.fetchone()
            if row:
                return row[0]
            raise NoResultsError('No snapshot cycle found.')
        except (DataError, IntegrityError, InternalError, NotSupportedError,
                OperationalError, ProgrammingError, NoResultsError) as e:
            raise MySQLError('snapshot_cycles', e)
