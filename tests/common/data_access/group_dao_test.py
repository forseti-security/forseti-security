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

from tests.unittest_utils import ForsetiTestCase
import mock

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import group_dao
from tests.common.data_access.test_data import fake_group_dao_data as fake_data


class GroupDaoTest(ForsetiTestCase):
    """Tests for the GroupDao."""

    @mock.patch.object(dao.Dao, '__init__', autospec=True)
    def setUp(self, mock_dao):
        mock_dao.return_value = None
        self.dao = group_dao.GroupDao()
        self.resource_name = 'groups'
        self.fake_group_email = 'foo@mycompany.com'
        self.fake_group_id = '11111'
        self.fake_timestamp = '22222'

    @mock.patch.object(dao.Dao, 'execute_sql_with_fetch', autospec=True)
    def test_get_group_id(self, mock_fetch):
        """Test get_group_members()."""
        mock_fetch.return_value = ({'group_id': '11111'},
                                   {'group_id': '22222'})
        group_id = self.dao.get_group_id(
            self.resource_name, self.fake_group_email, self.fake_timestamp)
        self.assertEqual('11111', group_id)

    @mock.patch.object(dao.Dao, 'execute_sql_with_fetch', autospec=True)
    def test_get_group_members_raises_error(self, mock_fetch):
        """Test get_group_members() raises error."""
        mock_fetch.side_effect = errors.MySQLError(
            self.resource_name, mock.MagicMock())

        with self.assertRaises(errors.MySQLError):
            self.dao.get_group_members(
                self.resource_name, self.fake_group_id, self.fake_timestamp)

    @mock.patch.object(group_dao.GroupDao, 'get_group_members', autospec=True)
    @mock.patch.object(group_dao.GroupDao, 'get_group_id', autospec=True)
    def test_get_recursive_members_of_group(self, mock_get_group_id,
                                            mock_get_group_members):
        """Test get_recursive_members_of_group()."""
        mock_get_group_id.return_value = '999999'
        mock_get_group_members.side_effect = (
            fake_data.GET_GROUP_MEMBERS_SIDE_EFFECT)
        
        all_members = self.dao.get_recursive_members_of_group(
            self.fake_group_email, self.fake_timestamp)
        
        self.assert_(fake_data.EXPECTED_ALL_MEMBERS, all_members)


if __name__ == '__main__':
    unittest.main()
