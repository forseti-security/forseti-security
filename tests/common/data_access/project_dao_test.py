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

"""Tests the ProjectDao."""

import json

from google.apputils import basetest
import mock

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import project


class ProjectDaoTest(basetest.TestCase):
    """Tests for the ProjectDao."""

    @mock.patch.object(_db_connector._DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        self.project_dao = project_dao.ProjectDao()

    def test_get_project_iam_policies(self):
        """Test that get_project_iam_policies() database methods are called.

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

        self.project_dao.conn = conn_mock
        self.project_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        resource_name = 'projects'
        fake_timestamp = '12345'
        fake_query = select_data.PROJECT_IAM_POLICIES_RAW.format(
            fake_timestamp, fake_timestamp)
        self.project_dao.get_project_policies(resource_name, fake_timestamp)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query)
        cursor_mock.fetchall.assert_called_once_with()

    def test_get_project_policies(self):
        """Test that get_project_policies() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake row of project data.

        Expect:
            * get_project_policies() call returns expected data: a dict of
              Projects and their IAM policies.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        iam_policies = [
            {'role': 'roles/something', 'members': ['user:a@b.c']},
            {'role': 'roles/other', 'members': ['user:x@y.z']},
        ]

        fake_project_policies = [
            ['11111', 'project-1', 'a1', 'ACTIVE',
             'organization', '1111', json.dumps(iam_policies[0])],
            ['22222', 'project-2', 'a2', 'ACTIVE',
             'organization', '2222', json.dumps(iam_policies[1])],
        ]

        self.project_dao.conn = conn_mock
        self.project_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fake_project_policies

        fake_timestamp = '11111'
        actual = self.project_dao.get_project_policies(
            'projects', fake_timestamp)

        project1 = project.Project(
            project_number=fake_project_policies[0][0],
            project_id=fake_project_policies[0][1],
        )
        project2 = project.Project(
            project_number=fake_project_policies[1][0],
            project_id=fake_project_policies[1][1],
        )
        expected = {
            project1: iam_policies[0],
            project2: iam_policies[1],
        }

        self.assertEqual(expected, actual)

    def test_get_project_policies_query_failed_handles_error(self):
        """Test that a failed get_project_policies() handles the error.

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

        self.project_dao.conn = conn_mock
        self.project_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError
        project_dao.LOGGER = mock.MagicMock()

        fake_timestamp = '11111'
        self.project_dao.get_project_policies('projects', fake_timestamp)

        self.assertEqual(1, project_dao.LOGGER.error.call_count)


if __name__ == '__main__':
    basetest.main()
