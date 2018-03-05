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

"""Tests the Folder resource"""

from datetime import datetime

import mock
import unittest

# pylint: disable=line-too-long
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util.date_time import UtilDateTimedValueErrorException
from google.cloud.forseti.common.util.date_time import UtilDateTimeTypeErrorException
from tests.unittest_utils import ForsetiTestCase
# pylint: enable=line-too-long


class DateTimeTest(ForsetiTestCase):
    """Test Folder resource."""

    def setUp(self):
        pass

    def get_utc_now_timestamp_human_is_a_string(self):
        """Ensure the get_utc_now_timestamp* functions return strings."""

        response_type = type(date_time.get_utc_now_timestamp())
        self.assertIsInstance(response_type, '')

        response_type = type(date_time.get_utc_now_timestamp_human())
        self.assertIsInstance(response_type, '')

    def get_utc_now_datetime_returns_datetime(self):
        """Ensure that get_utc_now_datetime returns a datetime object."""
        response_type = date_time.get_utc_now_datetime()
        self.assertIsInstance(response_type, type(datetime))

    @mock.patch.object(datetime, 'strptime')
    def get_datetime_from_string_should_raise(self, mock_datetime):
        """Ensure that get_datetime_from string raises correctly."""

        mock_datetime.side_effect = [TypeError, ValueError]

        with self.assertRaises(UtilDateTimeTypeErrorException):
            date_time.get_datetime_from_string('','')

        mock_datetime.assert_called_once_with('', '')

        with self.assertRaises(UtilDateTimedValueErrorException):
            date_time.get_datetime_from_string('','')

        mock_datetime.assert_once_with('', '')

if __name__ == '__main__':
    unittest.main()