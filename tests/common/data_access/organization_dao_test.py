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


class OrgDaoTest(basetest.TestCase):
    """Tests for the OrganizationDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        self.org_dao = organization_dao.OrganizationDao()

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

        resource_name = 'organizations'
        fake_timestamp = '11111'
        fake_query = select_data.ORGANIZATIONS.format(fake_timestamp)
        self.org_dao.get_organizations(resource_name, fake_timestamp)

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

        fake_orgs = [
            ['111111111111',
             'organizations/111111111111',
             'Organization1',
             'ACTIVE',
             '2015-09-09 00:01:01'],
            ['222222222222',
             'organizations/222222222222',
             'Organization2',
             'ACTIVE',
             '2015-10-10 00:02:02'],
        ]

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fake_orgs

        resource_name = 'organizations'
        fake_timestamp = '11111'
        fake_query = select_data.ORGANIZATIONS.format(fake_timestamp)
        orgs = self.org_dao.get_organizations(resource_name, fake_timestamp)

        expected_orgs = [
            organization.Organization(
                fake_orgs[0][0],
                org_name=fake_orgs[0][2],
                lifecycle_state=fake_orgs[0][3]),
            organization.Organization(
                fake_orgs[1][0],
                org_name=fake_orgs[1][2],
                lifecycle_state=fake_orgs[1][3]),
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

        resource_name = 'organizations'
        fake_timestamp = '11111'
        fake_query = select_data.ORGANIZATIONS.format(fake_timestamp)

        with self.assertRaises(errors.MySQLError):
            orgs = self.org_dao.get_organizations(resource_name, fake_timestamp)
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

        org_id = '1111111111111'
        fake_timestamp = '12345'
        fake_query = select_data.ORGANIZATION_BY_ID.format(fake_timestamp)
        self.org_dao.get_organization(fake_timestamp, org_id)

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

        fake_org = [
            '111111111111',
            'organizations/111111111111',
            'Organization1',
            'ACTIVE',
            '2015-09-09 00:01:01']

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchone.return_value = fake_org

        org_id = fake_org[0]
        fake_timestamp = '11111'
        org = self.org_dao.get_organization(fake_timestamp, org_id)

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

        fake_org = [
            '111111111111',
            'organizations/111111111111',
            'Organization1',
            'ACTIVE',
            '2015-09-09 00:01:01']

        self.org_dao.conn = conn_mock
        self.org_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.execute.side_effect = DataError

        org_id = fake_org[0]
        fake_timestamp = '11111'

        with self.assertRaises(errors.MySQLError):
            org = self.org_dao.get_organization(fake_timestamp, org_id)

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

        resource_name = 'organizations'
        fake_timestamp = '12345'
        fake_query = select_data.ORG_IAM_POLICIES.format(fake_timestamp)
        self.org_dao.get_org_iam_policies(resource_name, fake_timestamp)

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

        org_id = '1111111111'
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

        fake_timestamp = '11111'
        actual = self.org_dao.get_org_iam_policies(
            'organizations', fake_timestamp)

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


        fake_timestamp = '11111'
        self.org_dao.get_org_iam_policies('organizations', fake_timestamp)

        self.assertEqual(1, organization_dao.LOGGER.error.call_count)

if __name__ == '__main__':
    basetest.main()
