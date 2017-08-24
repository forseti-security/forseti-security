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

"""Tests the BucketDao."""

import json

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

from MySQLdb import DataError

from google.cloud.security.common.data_access import _db_connector
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import bucket_dao
from google.cloud.security.common.data_access.sql_queries import select_data


class BucketDaoTest(ForsetiTestCase):
    """Tests for the BucketDao."""

    FAKE_PROJECT_NUMBERS = ['11111']

    @mock.patch.object(_db_connector.DbConnector, '__init__', autospec=True)
    def setUp(self, mock_db_connector):
        mock_db_connector.return_value = None
        self.bucket_dao = bucket_dao.BucketDao()
        self.fetch_mock = mock.MagicMock()
        self.bucket_dao.execute_sql_with_fetch = self.fetch_mock
        self.resource_name = 'buckets_acl'
        self.fake_timestamp = '12345'

    def test_get_buckets_by_project_number(self):
        """Test get_buckets_by_project_number()."""
        fake_query = select_data.BUCKETS_BY_PROJECT_ID.format(
            self.fake_timestamp,
            self.FAKE_PROJECT_NUMBERS[0])
        self.bucket_dao.get_buckets_by_project_number(
            self.resource_name,
            self.fake_timestamp,
            self.FAKE_PROJECT_NUMBERS[0])

        self.fetch_mock.assert_called_once_with(
            self.resource_name, fake_query, (self.FAKE_PROJECT_NUMBERS[0],))

    def test_get_project_numbers_raises_error(self):
        """Test get_project_numbers() raises a MySQLError."""
        self.fetch_mock.side_effect = (
            errors.MySQLError(self.resource_name, mock.MagicMock()))

        with self.assertRaises(errors.MySQLError):
            self.bucket_dao.get_buckets_by_project_number(
                self.resource_name,
                self.fake_timestamp,
                self.FAKE_PROJECT_NUMBERS[0])

    def test_get_buckets_acls(self):
        """Test get_buckets_acls()."""
        fake_query_acls = select_data.BUCKET_ACLS.format(
            self.fake_timestamp)
        self.bucket_dao.get_buckets_acls(
            self.resource_name,
            self.fake_timestamp)

        self.fetch_mock.assert_called_once_with(
            self.resource_name, fake_query_acls, None)

    def test_get_raw_buckets(self):
        """Test get_raw_buckets()."""
        fake_return = [{'bucket_id': 'bucketid', 'acl': {"foo": 1}}]

        self.fetch_mock.return_value = fake_return

        fake_query = select_data.RAW_BUCKETS.format(self.fake_timestamp)
        actual = self.bucket_dao.get_raw_buckets(self.fake_timestamp)

        self.assertEquals(fake_return, actual)


if __name__ == '__main__':
    unittest.main()
