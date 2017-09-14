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

"""Tests the OrganizationDao."""

import json

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import organization
from tests.common.gcp_type.test_data import fake_orgs


class OrgDaoTest(ForsetiTestCase):
    """Tests for the OrganizationDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.org_dao = organization_dao.OrganizationDao()
        self.fetch_mock = mock.MagicMock()
        self.org_dao.execute_sql_with_fetch = self.fetch_mock
        self.resource_name = 'organizations'
        self.fake_timestamp = '12345'
        self.fake_orgs_db_rows = fake_orgs.FAKE_ORGS_DB_ROWS
        self.fake_orgs_ok_iam_db_rows = fake_orgs.FAKE_ORGS_OK_IAM_DB_ROWS
        self.fake_orgs_bad_iam_db_rows = fake_orgs.FAKE_ORGS_BAD_IAM_DB_ROWS

    def test_get_organizations_is_called(self):
        """Test that get_organizations() database methods are called.

        Setup:
            Create magic mock for execute_sql_with_fetch().

        Expect:
            execute_sql_with_fetch mock is called once.
        """
        fake_query = select_data.ORGANIZATIONS.format(self.fake_timestamp)
        self.org_dao.get_organizations(self.resource_name, self.fake_timestamp)

        self.fetch_mock.assert_called_once_with(
            self.resource_name, fake_query, ())

    def test_get_organizations(self):
        """Test that get_organizations() returns expected data.

        Setup:
            Create magic mock for execute_sql_with_fetch().
            Create fake rows of org data.

        Expect:
            * get_organizations() call returns expected data: a list of
              Organizations.
        """
        self.fetch_mock.return_value = self.fake_orgs_db_rows

        fake_query = select_data.ORGANIZATIONS.format(self.fake_timestamp)
        orgs = self.org_dao.get_organizations(
            self.resource_name, self.fake_timestamp)

        expected_orgs = [
            organization.Organization(
                self.fake_orgs_db_rows[0]['org_id'],
                display_name=self.fake_orgs_db_rows[0]['display_name'],
                lifecycle_state=self.fake_orgs_db_rows[0]['lifecycle_state']),
            organization.Organization(
                self.fake_orgs_db_rows[1]['org_id'],
                display_name=self.fake_orgs_db_rows[1]['display_name'],
                lifecycle_state=self.fake_orgs_db_rows[1]['lifecycle_state']),
        ]

        self.assertEqual(expected_orgs, orgs)

    def test_get_orgs_query_failed_returns_emptylist(self):
        """Test that a failed get_organizations() returns an empty list.

        Setup:
            Create magic mock for execute_sql_with_fetch().

        Expect:
            * get_organizations() raises MySQLError.
        """
        self.fetch_mock.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())
        organization_dao.LOGGER = mock.MagicMock()

        fake_query = select_data.ORGANIZATIONS.format(self.fake_timestamp)

        with self.assertRaises(errors.MySQLError):
            orgs = self.org_dao.get_organizations(
                self.resource_name, self.fake_timestamp)
            self.fetch_mock.assert_called_once_with(
                self.resource_name, fake_query)

    def test_get_organization(self):
        """Test that get_organization() returns expected data.

        Setup:
            Create magic mock for execute_sql_with_fetch().
            Create fake row of org data.

        Expect:
            * get_organization() call returns expected data: a single
              Organization.
        """
        fake_org = self.fake_orgs_db_rows[0]

        self.fetch_mock.return_value = [fake_org]

        org_id = fake_org['org_id']
        org = self.org_dao.get_organization(org_id, self.fake_timestamp)

        expected_org = organization.Organization(
            fake_org['org_id'],
            display_name=fake_org['display_name'],
            lifecycle_state=fake_org['lifecycle_state'])

        self.assertEqual(expected_org, org)

    def test_get_org_query_failed_raises_error(self):
        """Test that a failed get_organization() raises a MySQLError.

        Setup:
            Create magic mock for execute_sql_with_fetch().

        Expect:
            Raises a MySQLError.
        """
        self.fetch_mock.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())

        org_id = self.fake_orgs_db_rows[0]['org_id']

        with self.assertRaises(errors.MySQLError):
            org = self.org_dao.get_organization(org_id, self.fake_timestamp)

    def test_get_org_iam_policies_is_called(self):
        """Test that get_org_iam_policies() database methods are called.

        Setup:
            Create magic mock for execute_sql_with_fetch().

        Expect:
            execute_sql_with_fetch() is called once.
        """
        fake_query = select_data.ORG_IAM_POLICIES.format(self.fake_timestamp)
        self.org_dao.get_org_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.fetch_mock.assert_called_once_with(
            self.resource_name, fake_query, ())

    def test_get_org_iam_policies(self):
        """Test that get_org_iam_policies() returns expected data.

        Setup:
            Create magic mock for execute_sql_with_fetch().
            Create fake row of org data.

        Expect:
            * get_org_iam_policies() call returns expected data: a dict of
              Organizations and their IAM policies.
        """
        org_id = self.fake_orgs_db_rows[0]['org_id']
        iam_policy = {
            'role': 'roles/something',
            'members': ['user:a@b.c']
        }

        fake_org_iam_policies = [
            {'org_id': org_id,
             'iam_policy': json.dumps(iam_policy)}
        ]

        self.fetch_mock.return_value = fake_org_iam_policies

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
            Create magic mock for execute_sql_with_fetch().

        Expect:
            Raises a MySQLError.
        """
        self.fetch_mock.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())
        organization_dao.LOGGER = mock.MagicMock()

        with self.assertRaises(errors.MySQLError):
            self.org_dao.get_org_iam_policies(
                self.resource_name, self.fake_timestamp)

    def test_get_org_iam_policies_malformed_json_error_handled(self):
        """Test malformed json error is handled in get_org_iam_policies().

        Setup:
            Create magic mock for execute_sql_with_fetch().

        Expect:
            Log a warning and skip the row.
        """
        self.fetch_mock.return_value = self.fake_orgs_bad_iam_db_rows
        organization_dao.LOGGER = mock.MagicMock()

        expected_org = organization.Organization(
            self.fake_orgs_bad_iam_db_rows[0]['org_id'])
        expected_iam = json.loads(
            self.fake_orgs_bad_iam_db_rows[0]['iam_policy'])

        expected = {
            expected_org: expected_iam
        }

        actual = self.org_dao.get_org_iam_policies(
            self.resource_name, self.fake_timestamp)

        self.assertEqual(1, organization_dao.LOGGER.warn.call_count)
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    unittest.main()
