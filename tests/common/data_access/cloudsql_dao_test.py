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

"""Tests the CloudSqlDao."""

import json

from google.apputils import basetest
import mock

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import cloudsql_dao
from google.cloud.security.common.data_access.sql_queries import select_data


class CloudsqlDaoTest(basetest.TestCase):
	"""Tests for the CloudsqlDao."""

	FAKE_PROJECT_NUMBERS = ['11111']

	@mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
	def setUp(self, mock_db_connector):
		mock_db_connector.return_value = None
		self.cloudsql_dao = cloudsql_dao.CloudsqlDao()
		self.resource_name = 'cloudsql_instances'
		self.fake_timestamp = '12345'

	def test_get_cloudsql_acls(self):
		"""Test get_cloudsql_acls()."""
		conn_mock = mock.MagicMock()
		cursor_mock = mock.MagicMock()
		fetch_mock = mock.MagicMock()

		self.cloudsql_dao.conn = conn_mock
		self.cloudsql_dao.conn.cursor.return_value = cursor_mock
		cursor_mock.fetchall.return_value = fetch_mock

		fake_query = select_data.CLOUDSQL_ACLS.format(
			self.fake_timestamp, 
			self.FAKE_PROJECT_NUMBERS[0])
		self.cloudsql_dao.get_cloudsql_acls(
			self.resource_name, 
			self.fake_timestamp)

		cursor_mock.execute.assert_called_with(fake_query, None)
		cursor_mock.fetchall.assert_called_with()

	def test_get_cloudsql_acls_raises_error(self):
		"""Test get_cloudsql_acls() raises a MySQLError."""
		fetch_mock = mock.MagicMock()
		self.cloudsql_dao.execute_sql_with_fetch = fetch_mock
		fetch_mock.side_effect = (
			errors.MySQLError(self.resource_name, mock.MagicMock()))

		with self.assertRaises(errors.MySQLError):
			self.cloudsql_dao.get_cloudsql_acls(
				self.resource_name, 
				self.fake_timestamp)

	def test_get_cloudsql_instance_acl_map(self):
		"""Test get_cloudsql_instance_acl_map()."""
		conn_mock = mock.MagicMock()
		cursor_mock = mock.MagicMock()
		fetch_mock = mock.MagicMock()

		self.cloudsql_dao.conn = conn_mock
		self.cloudsql_dao.conn.cursor.return_value = cursor_mock
		cursor_mock.fetchall.return_value = fetch_mock

		fake_query_acls = select_data.CLOUDSQL_ACLS.format(
			self.fake_timestamp)
		self.cloudsql_dao._get_cloudsql_instance_acl_map(
			self.resource_name, 
			self.fake_timestamp)

		cursor_mock.execute.assert_called_once_with(fake_query_acls, None)
		cursor_mock.fetchall.assert_called_once_with()

	def test_get_cloudsql_instance_acl_map_raises_error(self):
		"""Test _get_cloudsql_instance_acl_map() raises a MySQLError."""
		fetch_mock = mock.MagicMock()
		self.cloudsql_dao.execute_sql_with_fetch = fetch_mock
		fetch_mock.side_effect = (
			errors.MySQLError(self.resource_name, mock.MagicMock()))

		with self.assertRaises(errors.MySQLError):
			self.cloudsql_dao._get_cloudsql_instance_acl_map(
				self.resource_name, 
				self.fake_timestamp)
