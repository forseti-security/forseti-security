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

"""Tests the OrganizationDao."""

import json

from google.apputils import basetest
import mock

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import organization
from tests.common.gcp_type.test_data import fake_orgs


class OrgDaoTest(basetest.TestCase):
    """Tests for the OrganizationDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        self.org_dao = organization_dao.OrganizationDao()
        self.resource_name = 'organizations'
        self.fake_timestamp = '12345'
        self.fake_orgs_db_rows = fake_orgs.FAKE_ORGS_DB_ROWS
        self.fake_orgs_ok_iam_db_rows = fake_orgs.FAKE_ORGS_OK_IAM_DB_ROWS
        self.fake_orgs_bad_iam_db_rows = fake_orgs.FAKE_ORGS_BAD_IAM_DB_ROWS

    def test_get_organizations_is_called(self):
        """Test that get_organizations() database methods are called.

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

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        fake_query = select_data.ORGANIZATIONS.format(self.fake_timestamp)
        self.org_dao.get_organizations(self.resource_name, self.fake_timestamp)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query)
        cursor_mock.fetchall.assert_called_once_with()

    def test_get_organizations(self):
        """Test that get_organizations() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake rows of org data.

        Expect:
            * get_organizations() call returns expected data: a list of
              Organizations.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()


        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = self.fake_orgs_db_rows

        fake_query = select_data.ORGANIZATIONS.format(self.fake_timestamp)
        orgs = self.org_dao.get_organizations(
            self.resource_name, self.fake_timestamp)

        expected_orgs = [
            organization.Organization(
                self.fake_orgs_db_rows[0][0],
                org_name=self.fake_orgs_db_rows[0][2],
                lifecycle_state=self.fake_orgs_db_rows[0][3]),
            organization.Organization(
                self.fake_orgs_db_rows[1][0],
                org_name=self.fake_orgs_db_rows[1][2],
                lifecycle_state=self.fake_orgs_db_rows[1][3]),
        ]

        self.assertEqual(expected_orgs, orgs)

    def test_get_orgs_query_failed_returns_emptylist(self):
        """Test that a failed get_organizations() returns an empty list.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch

        Expect:
            * organization_dao.LOGGER.error() is called once.
            * get_organizations() returns an empty list.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError
        organization_dao.LOGGER = mock.MagicMock()

        fake_query = select_data.ORGANIZATIONS.format(self.fake_timestamp)

        with self.assertRaises(errors.MySQLError):
            orgs = self.org_dao.get_organizations(
                self.resource_name, self.fake_timestamp)
            cursor_mock.execute.assert_called_once_with(fake_query)

    def test_get_organization_is_called(self):
        """Test that get_organization() database methods are called.

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

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone.return_value = fetch_mock

        org_id = self.fake_orgs_db_rows[0][0]
        fake_query = select_data.ORGANIZATION_BY_ID.format(self.fake_timestamp)
        self.org_dao.get_organization(self.fake_timestamp, org_id)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query, org_id)
        cursor_mock.fetchone.assert_called_once_with()

    def test_get_organization(self):
        """Test that get_organization() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake row of org data.

        Expect:
            * get_organization() call returns expected data: a single
              Organization.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        fake_org = self.fake_orgs_db_rows[0]

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone.return_value = fake_org

        org_id = fake_org[0]
        org = self.org_dao.get_organization(self.fake_timestamp, org_id)

        expected_org = organization.Organization(
            fake_org[0],
            org_name=fake_org[2],
            lifecycle_state=fake_org[3])

        self.assertEqual(expected_org, org)

    def test_get_org_query_failed_raises_error(self):
        """Test that a failed get_organization() raises a MySQLError.

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

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError

        org_id = self.fake_orgs_db_rows[0][0]

        with self.assertRaises(errors.MySQLError):
            org = self.org_dao.get_organization(self.fake_timestamp, org_id)

    def test_get_org_iam_policies_is_called(self):
        """Test that get_org_iam_policies() database methods are called.

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

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        fake_query = select_data.ORG_IAM_POLICIES.format(self.fake_timestamp)
        self.org_dao.get_org_iam_policies(
            self.resource_name, self.fake_timestamp)

        conn_mock.cursor.assert_called_once_with()
        cursor_mock.execute.assert_called_once_with(fake_query)
        cursor_mock.fetchall.assert_called_once_with()

    def test_get_org_iam_policies(self):
        """Test that get_org_iam_policies() returns expected data.

        Setup:
            Create magic mocks for:
              * conn
              * cursor
              * fetch
            Create fake row of org data.

        Expect:
            * get_org_iam_policies() call returns expected data: a dict of
              Organizations and their IAM policies.
        """
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()

        org_id = self.fake_orgs_db_rows[0][0]
        iam_policy = {
            'role': 'roles/something',
            'members': ['user:a@b.c']
        }

        fake_org_iam_policies = [
            [org_id, json.dumps(iam_policy)]
        ]

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fake_org_iam_policies

        actual = self.org_dao.get_org_iam_policies(
            self.resource_name, self.fake_timestamp)

        org = organization.Organization(org_id)
        expected = {
            org: iam_policy
        }

        self.assertEqual(expected, actual)

    def test_get_org_iam_policies_query_failed_handles_error(self):
        """Test that a failed get_org_iam_policies() handles the error.

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

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError
        organization_dao.LOGGER = mock.MagicMock()

        self.org_dao.get_org_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, organization_dao.LOGGER.error.call_count)

    def test_get_org_iam_policies_malformed_json_error_handled(self):
        """Test malformed json error is handled in get_org_iam_policies().

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

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall = fetch_mock
        fetch_mock.return_value = self.fake_orgs_bad_iam_db_rows
        organization_dao.LOGGER = mock.MagicMock()

        expected_org = organization.Organization(
            self.fake_orgs_bad_iam_db_rows[0][0])
        expected_iam = json.loads(self.fake_orgs_bad_iam_db_rows[0][1])

        expected = {
            expected_org: expected_iam
        }

        actual = self.org_dao.get_org_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, organization_dao.LOGGER.warn.call_count)
        self.assertEqual(expected, actual)

if __name__ == '__main__':
    basetest.main()
