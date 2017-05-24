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

"""Tests the Dao."""

import json

from tests.unittest_utils import ForsetiTestCase
import mock

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access.sql_queries import select_data


class DaoTest(ForsetiTestCase):
    """Tests for the Dao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.dao = dao.Dao()
        self.fake_timestamp = '12345'
        self.resource_projects = 'projects'

    def test_create_snapshot_table_projects(self):
        """Test create_snapshot_table.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            * cursor() is called.
            * cursor.execute() is called.
            * cursor.fetchall() is called.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()
        fetch_mock = mock.MagicMock()

        self.dao.conn = conn_mock
        self.dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        actual_tablename = self.dao._create_snapshot_table(
            self.resource_projects, self.fake_timestamp)

        expected_tablename = ('%s_%s' %
            (self.resource_projects, self.fake_timestamp))

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(
            dao.CREATE_TABLE_MAP[self.resource_projects].format(
                expected_tablename))

        self.assertEqual(expected_tablename, actual_tablename)

    def test_get_latest_snapshot_timestamp(self):
        """Test create_snapshot_table.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            * cursor() is called.
            * cursor.execute() is called.
            * cursor.fetchone() is called.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()
        fetch_mock = mock.MagicMock()

        expected_db_row = ['123456']

        self.dao.conn = conn_mock
        self.dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone = fetch_mock
        fetch_mock.return_value = ['123456']

        statuses = ('SUCCESS',)
        filter_clause = dao.SNAPSHOT_STATUS_FILTER_CLAUSE.format('%s')

        actual = self.dao.get_latest_snapshot_timestamp(statuses)

        conn_mock.cursor.assert_called_once_with()
        fetch_mock.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(
            select_data.LATEST_SNAPSHOT_TIMESTAMP + filter_clause, statuses)
        self.assertEqual(expected_db_row[0], actual)

    def test_get_latest_snapshot_timestamp_invalid_data_ok(self):
        """Test create_snapshot_table.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            * cursor() is called.
            * cursor.execute() is called.
            * cursor.fetchone() is called.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()
        fetch_mock = mock.MagicMock()

        expected_db_row = ['123456']

        self.dao.conn = conn_mock
        self.dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone = fetch_mock
        fetch_mock.return_value = ['123456']

        expected_statuses = ('SUCCESS',)
        filter_clause = dao.SNAPSHOT_STATUS_FILTER_CLAUSE.format('%s')

        actual = self.dao.get_latest_snapshot_timestamp('asdfasdf')

        conn_mock.cursor.assert_called_once_with()
        fetch_mock.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(
            select_data.LATEST_SNAPSHOT_TIMESTAMP + filter_clause,
            expected_statuses)
        self.assertEqual(expected_db_row[0], actual)

    def test_get_latest_snapshot_timestamp_raises_error_no_results(self):
        """Test create_snapshot_table() raises error on no results.

        Setup:
            Create magic mocks for:
              * conn
              * cursor

        Expect:
            Raise MySQLError for no results.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()
        exec_mock = mock.MagicMock()

        self.dao.conn = conn_mock
        self.dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute = exec_mock
        exec_mock.side_effect = errors.NoResultsError

        expected_statuses = ('SUCCESS',)
        filter_clause = dao.SNAPSHOT_STATUS_FILTER_CLAUSE.format('%s')

        with self.assertRaises(errors.MySQLError):
            self.dao.get_latest_snapshot_timestamp('asdfasdf')


if __name__ == '__main__':
    unittest.main()
