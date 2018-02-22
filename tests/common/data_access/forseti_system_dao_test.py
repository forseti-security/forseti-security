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

"""Tests the ForsetiSystemDao."""

import json

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import forseti_system_dao
from google.cloud.security.common.data_access.sql_queries import cleanup_tables_sql


class ForsetiSystemDaoTest(ForsetiTestCase):
    """Tests for the ForsetiSystemDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.system_dao = forseti_system_dao.ForsetiSystemDao(
            global_configs={'db_name': 'forseti_security'})
        self.fetch_mock = mock.MagicMock()
        self.commit_mock = mock.MagicMock()
        self.system_dao.execute_sql_with_fetch = self.fetch_mock
        self.system_dao.execute_sql_with_commit = self.commit_mock

    def test_cleanup_inventory_tables(self):
        """Test cleanup_inventory_tables(int)"""
        self.fetch_mock.return_value = [{'table': 'foo'}, {'table': 'bar'}]
        self.system_dao.cleanup_inventory_tables(7)

        self.fetch_mock.assert_called_once_with(
            cleanup_tables_sql.RESOURCE_NAME,
            cleanup_tables_sql.SELECT_SNAPSHOT_TABLES_OLDER_THAN,
            [7, 'forseti_security'])

        calls = [mock.call(
            cleanup_tables_sql.RESOURCE_NAME,
            cleanup_tables_sql.DROP_TABLE.format('foo'),
            None),
            mock.call(
            cleanup_tables_sql.RESOURCE_NAME,
            cleanup_tables_sql.DROP_TABLE.format('bar'),
            None)]
        self.commit_mock.assert_has_calls(calls)

if __name__ == '__main__':
    unittest.main()
