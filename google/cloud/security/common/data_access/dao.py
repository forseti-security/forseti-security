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

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import load_data_sql_provider
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.errors import NoResultsError
from google.cloud.security.common.data_access.sql_queries import create_tables
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)

CREATE_TABLE_MAP = {
    # backend services
    'backend_services': create_tables.CREATE_BACKEND_SERVICES_TABLE,

    # bigquery
    'bigquery_datasets': create_tables.CREATE_BIGQUERY_DATASETS_TABLE,

    # buckets
    'buckets': create_tables.CREATE_BUCKETS_TABLE,
    'raw_buckets': create_tables.CREATE_RAW_BUCKETS_TABLE,
    'buckets_acl': create_tables.CREATE_BUCKETS_ACL_TABLE,

    # cloudsql
    'cloudsql_instances': create_tables.CREATE_CLOUDSQL_INSTANCES_TABLE,
    'cloudsql_ipaddresses': create_tables.CREATE_CLOUDSQL_IPADDRESSES_TABLE,
    'cloudsql_ipconfiguration_authorizednetworks':\
        create_tables.CREATE_CLOUDSQL_IPCONFIGURATION_AUTHORIZEDNETWORKS,
    'cloudsql_acl_violations':\
        create_tables.CREATE_CLOUDSQL_ACL_VIOLATIONS_TABLE,

    # folders
    'folders': create_tables.CREATE_FOLDERS_TABLE,
    'folder_iam_policies': create_tables.CREATE_FOLDER_IAM_POLICIES_TABLE,
    'raw_folder_iam_policies': (
        create_tables.CREATE_RAW_FOLDER_IAM_POLICIES_TABLE),

    # load balancer
    'forwarding_rules': create_tables.CREATE_FORWARDING_RULES_TABLE,

    # firewall_rules
    'firewall_rules': create_tables.CREATE_FIREWALL_RULES_TABLE,

    # groups
    'groups': create_tables.CREATE_GROUPS_TABLE,
    'group_members': create_tables.CREATE_GROUP_MEMBERS_TABLE,

    # instances
    'instances': create_tables.CREATE_INSTANCES_TABLE,

    # organizations
    'organizations': create_tables.CREATE_ORGANIZATIONS_TABLE,
    'org_iam_policies': create_tables.CREATE_ORG_IAM_POLICIES_TABLE,
    'raw_org_iam_policies': create_tables.CREATE_RAW_ORG_IAM_POLICIES_TABLE,

    # projects
    'projects': create_tables.CREATE_PROJECT_TABLE,
    'project_iam_policies': create_tables.CREATE_PROJECT_IAM_POLICIES_TABLE,
    'raw_project_iam_policies':
        create_tables.CREATE_RAW_PROJECT_IAM_POLICIES_TABLE,

    # rule violations
    'buckets_acl_violations':
        create_tables.CREATE_BUCKETS_ACL_VIOLATIONS_TABLE,
    'violations': create_tables.CREATE_VIOLATIONS_TABLE,
}

SNAPSHOT_STATUS_FILTER_CLAUSE = ' where status in ({})'


class Dao(_db_connector.DbConnector):
    """Data access object (DAO)."""

    @staticmethod
    def map_row_to_object(object_class, row):
        """Instantiate an object from database row.

        TODO: Make this go away when we start using an ORM.

        Args:
            object_class: The object class to create.
            row: The database row to map.

        Returns:
            A new "obj_class", created from the row.
        """
        return object_class(**row)

    def _create_snapshot_table(self, resource_name, timestamp):
        """Creates a snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            snapshot_table_name: String of the created snapshot table.
        """
        snapshot_table_name = self._create_snapshot_table_name(
            resource_name, timestamp)
        create_table_sql = CREATE_TABLE_MAP[resource_name]
        create_snapshot_sql = create_table_sql.format(snapshot_table_name)
        cursor = self.conn.cursor()
        cursor.execute(create_snapshot_sql)
        return snapshot_table_name

    @staticmethod
    def _create_snapshot_table_name(resource_name, timestamp):
        """Create the snapshot table if it doesn't exist.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            String of the created snapshot table name.
        """
        return resource_name + '_' + timestamp

    def _get_snapshot_table(self, resource_name, timestamp):
        """Returns a snapshot table name.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
            snapshot_table_name: String of the created snapshot table.
        """
        try:
            snapshot_table_name = self._create_snapshot_table(
                resource_name, timestamp)
        except OperationalError:
            # TODO: find a better way to handle this. I want this method
            # to be resilient when the table has already been created
            # so that it can support inserting new data. This will catch
            # a sql 'table already exist' error and alter the flow.
            snapshot_table_name = self._create_snapshot_table_name(
                resource_name, timestamp)
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
        with csv_writer.write_csv(resource_name, data) as csv_file:
            try:
                snapshot_table_name = self._get_snapshot_table(
                    resource_name, timestamp)
                load_data_sql = load_data_sql_provider.provide_load_data_sql(
                    resource_name, csv_file.name, snapshot_table_name)
                LOGGER.debug('SQL: %s', load_data_sql)
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

    def select_group_ids(self, resource_name, timestamp):
        """Select the group ids from a snapshot table.

        Args:
            resource_name: String of the resource name.
            timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

        Returns:
             A list of group ids.

        Raises:
            MySQLError: An error with MySQL has occurred.
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

    def get_latest_snapshot_timestamp(self, statuses):
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
