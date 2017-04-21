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

"""Tests the FolderDao."""

import json

from google.apputils import basetest
import mock

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import folder as gcp_folder
from tests.common.gcp_type.test_data import fake_folders


class FolderDaoTest(basetest.TestCase):
    """Tests for the FolderDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        self.folder_dao = folder_dao.FolderDao()
        self.resource_name = 'folders'
        self.fake_timestamp = '12345'
        self.fake_folders_db_rows = fake_folders.FAKE_FOLDERS_DB_ROWS
        self.fake_folders_ok_iam_db_rows = \
            fake_folders.FAKE_FOLDERS_OK_IAM_DB_ROWS
        self.fake_folders_bad_iam_db_rows = \
            fake_folders.FAKE_FOLDERS_BAD_IAM_DB_ROWS

    def test_get_folders_is_called(self):
        """Test that get_folders() database methods are called.

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

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        fake_query = select_data.FOLDERS.format(self.fake_timestamp)
        self.folder_dao.get_folders(self.resource_name, self.fake_timestamp)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query)
        cursor_mock.fetchall.assert_called_once_with()

    def test_get_folders(self):
        """Test that get_folders() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake rows of folder data.

        Expect:
            * get_folders() call returns expected data: a list of Folders.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()


        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = self.fake_folders_db_rows

        fake_query = select_data.FOLDERS.format(self.fake_timestamp)
        folders = self.folder_dao.get_folders(
            self.resource_name, self.fake_timestamp)

        expected_folders = [
            gcp_folder.Folder(
                self.fake_folders_db_rows[0][0],
                display_name=self.fake_folders_db_rows[0][2],
                lifecycle_state=self.fake_folders_db_rows[0][3]),
            gcp_folder.Folder(
                self.fake_folders_db_rows[1][0],
                display_name=self.fake_folders_db_rows[1][2],
                lifecycle_state=self.fake_folders_db_rows[1][3]),
        ]

        self.assertEqual(expected_folders, folders)

    def test_get_folders_query_failed_returns_emptylist(self):
        """Test that a failed get_folders() returns an empty list.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            * folder_dao.LOGGER.error() is called once.
            * get_folders() returns an empty list.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError
        folder_dao.LOGGER = mock.MagicMock()

        fake_query = select_data.FOLDERS.format(self.fake_timestamp)

        with self.assertRaises(errors.MySQLError):
            folders = self.folder_dao.get_folders(
                self.resource_name, self.fake_timestamp)
            cursor_mock.execute.assert_called_once_with(fake_query)

    def test_get_folder_is_called(self):
        """Test that get_folder() database methods are called.

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

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone.return_value = self.fake_folders_db_rows[0]

        folder_id = self.fake_folders_db_rows[0][0]
        fake_query = select_data.FOLDER_BY_ID.format(
            self.fake_timestamp, self.fake_timestamp)
        self.folder_dao.get_folder(self.fake_timestamp, folder_id)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query, folder_id)
        cursor_mock.fetchone.assert_called_once_with()

    def test_get_folder(self):
        """Test that get_folder() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake row of folder data.

        Expect:
            * get_folder() call returns expected data: a single Folder.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        fake_folder = self.fake_folders_db_rows[0]

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone.return_value = fake_folder

        folder_id = fake_folder[0]
        folder = self.folder_dao.get_folder(self.fake_timestamp, folder_id)

        expected_folder = gcp_folder.Folder(
            fake_folder[0],
            display_name=fake_folder[2],
            lifecycle_state=fake_folder[3])

        self.assertEqual(expected_folder, folder)

    def test_get_folder_query_failed_raises_error(self):
        """Test that a failed get_folder() raises a MySQLError.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            Raises a MySQLError.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError

        folder_id = self.fake_folders_db_rows[0][0]

        with self.assertRaises(errors.MySQLError):
            folder = self.folder_dao.get_folder(
                self.fake_timestamp, folder_id)

    def test_get_folder_iam_policies_is_called(self):
        """Test that get_folder_iam_policies() database methods are called.

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

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        fake_query = select_data.FOLDER_IAM_POLICIES.format(
            self.fake_timestamp, self.fake_timestamp)
        self.folder_dao.get_folder_iam_policies(
            self.resource_name, self.fake_timestamp)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query)
        cursor_mock.fetchall.assert_called_once_with()

    def test_get_folder_iam_policies(self):
        """Test that get_folder_iam_policies() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake row of folder data.

        Expect:
            * get_folder_iam_policies() call returns expected data: a dict of
              Folders and their IAM policies.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        folder_id = self.fake_folders_db_rows[0][0]
        iam_policy = {
            'role': 'roles/something',
            'members': ['user:a@b.c']
        }

        fake_folder_iam_policies = [
            [folder_id, 'folder1', 'ACTIVE', None, None, json.dumps(iam_policy)]
        ]

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fake_folder_iam_policies

        actual = self.folder_dao.get_folder_iam_policies(
            self.resource_name, self.fake_timestamp)

        folder = gcp_folder.Folder(folder_id)
        expected = {
            folder: iam_policy
        }

        self.assertEqual(expected, actual)

    def test_get_folder_iam_policies_query_failed_handles_error(self):
        """Test that a failed get_folder_iam_policies() handles the error.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            Raises a MySQLError.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError
        folder_dao.LOGGER = mock.MagicMock()

        self.folder_dao.get_folder_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, folder_dao.LOGGER.error.call_count)

    def test_get_folder_iam_policies_malformed_json_error_handled(self):
        """Test malformed json error is handled in get_folder_iam_policies().

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            Log a warning and skip the row.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()
        fetch_mock = mock.MagicMock()

        self.folder_dao.conn = conn_mock
        self.folder_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall = fetch_mock
        fetch_mock.return_value = self.fake_folders_bad_iam_db_rows
        folder_dao.LOGGER = mock.MagicMock()

        expected_folder = gcp_folder.Folder(
            self.fake_folders_bad_iam_db_rows[0][0])
        expected_iam = json.loads(self.fake_folders_bad_iam_db_rows[0][5])

        expected = {
            expected_folder: expected_iam
        }

        actual = self.folder_dao.get_folder_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, folder_dao.LOGGER.warn.call_count)
        self.assertEqual(expected, actual)

if __name__ == '__main__':
    basetest.main()
