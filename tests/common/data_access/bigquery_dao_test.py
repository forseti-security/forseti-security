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

"""Tests the BigqueryDao."""

import json

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import bigquery_dao
from google.cloud.security.common.data_access.sql_queries import select_data


class BigqueryDaoTest(ForsetiTestCase):
    """Tests for the BigqueryDao."""

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.bigquery_dao = bigquery_dao.BigqueryDao()
        self.resource_name = 'bigquery_datasets'
        self.fake_timestamp = '12345'

    def test_get_bigquery_acls(self):
        """Test get_bigquery_acls()."""
        conn_mock = mock.MagicMock()
        cursor_mock = mock.MagicMock()
        fetch_mock = mock.MagicMock()

        self.bigquery_dao.conn = conn_mock
        self.bigquery_dao.conn.cursor.return_value = cursor_mock
        cursor_mock.fetchall.return_value = fetch_mock

        fake_query_acls = select_data.BIGQUERY_ACLS.format(
            self.fake_timestamp)
        self.bigquery_dao.get_bigquery_acls(
            self.resource_name,
            self.fake_timestamp)

        cursor_mock.execute.assert_called_once_with(fake_query_acls, None)
        cursor_mock.fetchall.assert_called_once_with()


if __name__ == '__main__':
    unittest.main()
