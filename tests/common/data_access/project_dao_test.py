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

from tests.unittest_utils import ForsetiTestCase
import mock

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource
from tests.common.gcp_type.test_data import fake_projects


class ProjectDaoTest(ForsetiTestCase):
    """Tests for the ProjectDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.project_dao = project_dao.ProjectDao()
        self.fetch_mock = mock.MagicMock()
        self.project_dao.execute_sql_with_fetch = self.fetch_mock
        self.resource_name = 'projects'
        self.fake_timestamp = '12345'
        self.fake_projects_db_rows = fake_projects.FAKE_PROJECTS_DB_ROWS
        self.fake_projects_bad_iam_db_rows = \
            fake_projects.FAKE_PROJECTS_BAD_IAM_DB_ROWS

        self.fake_projects_iam_rows = \
            fake_projects.FAKE_PROJECTS_OK_IAM_DB_ROWS

    def test_get_project_numbers(self):
        """Test get_project_numbers().

        Setup:
            Format the fake query.

        Expect:
            execute_sql_with_fetch() called once.
        """

        fake_query = select_data.PROJECT_NUMBERS.format(self.fake_timestamp)
        self.project_dao.get_project_numbers(
            self.resource_name, self.fake_timestamp)

        self.fetch_mock.assert_called_once_with(
            self.resource_name, fake_query, ())

    def test_get_project_numbers_raises_error(self):
        """Test get_project_numbers() raises a MySQLError.

        Setup:
            Set execute_sql_with_fetch() side effect to MySQLError.

        Expect:
            get_project_numbers() raises a MySQLError.
        """
        self.fetch_mock.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())

        with self.assertRaises(errors.MySQLError):
            self.project_dao.get_project_numbers(
                self.resource_name, self.fake_timestamp)

    def test_get_project(self):
        """Test that get_project() returns expected data.

        Setup:
            Mock execute_sql_with_fetch() return value.
            Create fake row of project data.

        Expect:
            get_project() call returns expected data: a single Project.
        """
        fake_project = self.fake_projects_db_rows[0]
        self.fetch_mock.return_value = [fake_project]

        fake_query = select_data.PROJECT_BY_ID.format(
            self.fake_timestamp, self.fake_timestamp)
        actual = self.project_dao.get_project(
            fake_project['project_id'],
            self.fake_timestamp)

        self.assertEqual(
            self.project_dao.map_row_to_object(fake_project),
            actual)

    def test_get_project_iam_policies(self):
        """Test that get_project_iam_policies() database methods are called.

        Setup:
            Format the fake query.

        Expect:
            execute_sql_with_fetch() called once.
        """
        fake_query = select_data.PROJECT_IAM_POLICIES_RAW.format(
            self.fake_timestamp, self.fake_timestamp)
        self.project_dao.get_project_policies(
            resource.ResourceType.PROJECT, self.fake_timestamp)

        self.fetch_mock.assert_called_once_with(
            resource.ResourceType.PROJECT, fake_query, ())

    def test_get_project_policies(self):
        """Test that get_project_policies() returns expected data.

        Setup:
            Create magic mock for execute_sql_with_fetch().
            Create fake row of project data.

        Expect:
            * get_project_policies() call returns expected data: a dict of
              Projects and their IAM policies.
        """
        self.fetch_mock.return_value = self.fake_projects_iam_rows

        actual = self.project_dao.get_project_policies(
            'projects', self.fake_timestamp)

        expected_projects = [self.project_dao.map_row_to_object(r)
            for r in self.fake_projects_iam_rows]
        expected_iam = [json.loads(p['iam_policy'])
            for p in self.fake_projects_iam_rows]
        expected = dict(zip(expected_projects, expected_iam))

        self.assertEqual(expected, actual)

    def test_get_project_policies_query_failed_handles_error(self):
        """Test that a failed get_project_policies() handles the error.

        Setup:
            Set execute_sql_with_fetch() side effect to MySQLError.

        Expect:
            get_project_policies() raises a MySQLError.
        """
        self.fetch_mock.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())

        with self.assertRaises(errors.MySQLError):
            self.project_dao.get_project_policies(
                self.resource_name, self.fake_timestamp)

    def test_get_project_iam_policies_malformed_json_error_handled(self):
        """Test malformed json error is handled in get_project_policies().

        Setup:
            Set execute_sql_with_fetch() return value to fake data with bad
            malformed json.

        Expect:
            Log a warning and skip the row, such that the output only contains
            1 result (out of 2).
        """
        self.fetch_mock.return_value = self.fake_projects_bad_iam_db_rows
        project_dao.LOGGER = mock.MagicMock()

        ok_row = self.fake_projects_bad_iam_db_rows[0]

        expected_project = self.project_dao.map_row_to_object(ok_row)
        expected_iam = json.loads(ok_row['iam_policy'])

        expected = {
            expected_project: expected_iam
        }

        actual = self.project_dao.get_project_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, project_dao.LOGGER.warn.call_count)
        self.assertEqual(expected, actual)

    def test_get_projects(self):
        """Test get_projects().

        Setup:
            Set execute_sql_with_fetch() return value to fake data.

        Expected:
            Expected projects equal actual.
        """
        self.fetch_mock.return_value = self.fake_projects_iam_rows
        actual = self.project_dao.get_projects(self.fake_timestamp)

        expected = [self.project_dao.map_row_to_object(r)
            for r in self.fake_projects_iam_rows]

        self.assertEqual(expected, actual)

    def test_get_projects_raises_error_on_fetch_error(self):
        """Test get_projects() raises MySQLError on fetch error.

        Setup:
            Set execute_sql_with_fetch() side effect to MySQLError.

        Expected:
            get_projects() raises MySQLError.
        """
        self.fetch_mock.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())

        with self.assertRaises(errors.MySQLError):
            self.project_dao.get_projects(self.fake_timestamp)


if __name__ == '__main__':
    unittest.main()
