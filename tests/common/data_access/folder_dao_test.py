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

from tests.unittest_utils import ForsetiTestCase
import mock

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import folder as gcp_folder
from tests.common.gcp_type.test_data import fake_folders


class FolderDaoTest(ForsetiTestCase):
    """Tests for the FolderDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.folder_dao = folder_dao.FolderDao()
        self.fetch_mock = mock.MagicMock()
        self.folder_dao.execute_sql_with_fetch = self.fetch_mock
        self.resource_name = 'folders'
        self.fake_timestamp = '12345'
        self.fake_folders_db_rows = fake_folders.FAKE_FOLDERS_DB_ROWS
        self.fake_folders_ok_iam_db_rows = \
            fake_folders.FAKE_FOLDERS_OK_IAM_DB_ROWS
        self.fake_folders_bad_iam_db_rows = \
            fake_folders.FAKE_FOLDERS_BAD_IAM_DB_ROWS

    def test_get_folders(self):
        """Test that get_folders() returns expected data.

        Setup:
            Create magic mock for execute_sql_with_fetch().
            Create fake rows of folder data.

        Expect:
            * get_folders() call returns expected data: a list of Folders.
        """
        self.fetch_mock.return_value = self.fake_folders_db_rows

        fake_query = select_data.FOLDERS.format(self.fake_timestamp)
        actual = self.folder_dao.get_folders(
            self.resource_name, self.fake_timestamp)

        expected_folders = [
            self.folder_dao.map_row_to_object(row)
            for row in self.fake_folders_db_rows
        ]

        self.assertEqual(expected_folders, actual)

    def test_get_folder(self):
        """Test that get_folder() returns expected data.

        Setup:
            Mock execute_sql_with_fetch() return value.
            Create fake row of folder data.

        Expect:
            get_folder() call returns expected data: a single Folder.
        """
        fake_folder = self.fake_folders_db_rows[0]
        self.fetch_mock.return_value = [fake_folder]

        fake_query = select_data.FOLDER_BY_ID.format(
            self.fake_timestamp, self.fake_timestamp)
        actual = self.folder_dao.get_folder(
            fake_folder['folder_id'],
            self.fake_timestamp)

        self.assertEqual(
            self.folder_dao.map_row_to_object(fake_folder),
            actual)

    def test_get_folder_iam_policies(self):
        """Test that get_folder_iam_policies() returns expected data.

        Setup:
            Create magic mock for execute_sql_with_fetch().
            Create fake row of folder data.

        Expect:
            * get_folder_iam_policies() call returns expected data: a dict of
              Folders and their IAM policies.
        """
        folder_id = self.fake_folders_db_rows[0]['folder_id']
        iam_policy = {
            'role': 'roles/something',
            'members': ['user:a@b.c']
        }

        fake_folder_iam_policies = [
            {'folder_id': folder_id,
             'display_name': 'folder1',
             'lifecycle_state': 'ACTIVE',
             'parent_id': None,
             'parent_type': None,
             'iam_policy': json.dumps(iam_policy)}
        ]

        self.fetch_mock.return_value = fake_folder_iam_policies

        actual = self.folder_dao.get_folder_iam_policies(
            self.resource_name, self.fake_timestamp)

        folder = gcp_folder.Folder(folder_id)
        expected = {
            folder: iam_policy
        }

        self.assertEqual(expected, actual)

    def test_get_folder_iam_policies_malformed_json_error_handled(self):
        """Test malformed json error is handled in get_folder_iam_policies().

        Setup:
            Mock execute_sql_with_fetch() return value.
            Create mock for LOGGER.

        Expect:
            Log a warning and skip the row.
        """
        self.fetch_mock.return_value = self.fake_folders_bad_iam_db_rows
        folder_dao.LOGGER = mock.MagicMock()

        expected_folder = self.folder_dao.map_row_to_object(
            self.fake_folders_bad_iam_db_rows[0])
        expected_iam = json.loads(
            self.fake_folders_bad_iam_db_rows[0]['iam_policy'])

        expected = {
            expected_folder: expected_iam
        }

        actual = self.folder_dao.get_folder_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, folder_dao.LOGGER.warn.call_count)
        self.assertEqual(expected, actual)

if __name__ == '__main__':
    unittest.main()
