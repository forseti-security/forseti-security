# Copyright 2017 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-1.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test the date_time utility functions."""

from datetime import datetime

import mock
import unittest
from datetime import datetime

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import string_formats
from tests.unittest_utils import ForsetiTestCase


class DateTimeTest(ForsetiTestCase):
    """Test Folder resource."""

    def test_get_datetime_from_string(self):
        test_string = "2018-01-01T00:00:00Z"
        result = date_time.get_datetime_from_string(
            test_string, string_formats.TIMESTAMP_TIMEZONE)
        expected_result = datetime(2018, 1, 1, 0, 0, 0)
        self.assertEqual(expected_result, result)

    def test_get_unix_timestamp_from_string(self):
        test_string = "2018-01-01T00:00:00Z"
        result = date_time.get_unix_timestamp_from_string(test_string)
        expected_result = 1514764800
        self.assertEqual(expected_result, result)

    def test_get_utc_now_timestamp_human(self):
        # 2018/01/01 00:00:00.123456
        mock_date = datetime(2018, 1, 1, 0, 0, 0, 123456)
        result = date_time.get_utc_now_timestamp_human(mock_date)
        expected_result = "01 January 2018 - 00:00:00"
        self.assertEqual(expected_result, result)

    def test_get_utc_now_timestamp(self):
        # 2018/01/01 00:00:00.123456
        mock_date = datetime(2018, 1, 1, 0, 0, 0, 123456)
        result = date_time.get_utc_now_timestamp(mock_date)
        expected_result = "2018-01-01T00:00:00Z"
        self.assertEqual(expected_result, result)

    def test_get_utc_now_unix_timestamp(self):
        # 2018/01/01 00:00:00.123456
        mock_date = datetime(2018, 1, 1, 0, 0, 0, 123456)
        result = date_time.get_utc_now_unix_timestamp(mock_date)
        # Expected timestamp = 1514764800
        expected_result = 1514764800
        self.assertEqual(expected_result, result)

    def test_get_utc_now_microtimestamp(self):
        # 2018/01/01 00:00:00.123456
        mock_date = datetime(2018, 1, 1, 0, 0, 0, 123456)
        result = date_time.get_utc_now_microtimestamp(mock_date)
        # Expected timestamp = 1514764800 * 1000000 + 123456
        expected_result = 1514764800123456
        self.assertEqual(expected_result, result)

    def test_get_date_from_microtimestamp(self):
        # Timestamp = 1514764800 * 1000000 + 123456
        mock_timestamp = 1514764800123456
        # 2018/01/01 00:00:00.123456
        expected_result = datetime(2018, 1, 1, 0, 0, 0, 123456)
        result = date_time.get_date_from_microtimestamp(mock_timestamp)
        self.assertEqual(expected_result, result)


if __name__ == '__main__':
    unittest.main()
