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

"""Tests the GroupDao."""

import json

from google.apputils import basetest
import mock

from MySQLdb import DataError

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import group_dao
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.gcp_type import group
from google.cloud.security.common.gcp_type import group_member
from tests.common.gcp_type.test_data import fake_groups


def _get_expected_group_members(db_rows):
    members = {}
    for row in db_rows:
        group_id = row.get('group_id')
        member = group_member.GroupMember(
            member_role=row.get('member_role'),
            member_type=row.get('member_type'),
            member_email=row.get('member_email')
        )
        if group_id not in members:
            members[group_id] = []
        members[group_id].append(member)
    return members


class GroupDaoTest(basetest.TestCase):
    """Tests for the GroupDao."""

    @mock.patch.object(dao.Dao, '__init__', autospec=True)
    def setUp(self, mock_dao):
        #self.group_dao = mock.create_autospec(group_dao.GroupDao)
        self.group_dao = group_dao.GroupDao()
        self.resource_name = 'groups'
        self.fake_timestamp = '12345'
        self.fake_group_db_rows1 = fake_groups.FAKE_GROUPS_DB_ROWS
        self.fake_group_expected1 = _get_expected_group_members(
            self.fake_group_db_rows1)

    @mock.patch.object(dao.Dao, 'execute_sql_with_fetch', autospec=True)
    def test_get_group_users(self, mock_fetch):
        """Test get_group_users()."""
        mock_fetch.return_value = self.fake_group_db_rows1
        actual = self.group_dao.get_group_users(
            self.resource_name, self.fake_timestamp)
        expected = self.fake_group_expected1
        self.assertEqual(expected, actual)

    @mock.patch.object(dao.Dao, 'execute_sql_with_fetch', autospec=True)
    def test_get_group_users_raises_error(self, mock_fetch):
        """Test get_group_users() raises error."""
        mock_fetch.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())

        with self.assertRaises(errors.MySQLError):
            self.group_dao.get_group_users(
                self.resource_name, self.fake_timestamp)


if __name__ == '__main__':
    basetest.main()
