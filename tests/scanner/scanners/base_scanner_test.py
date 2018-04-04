# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""BaseScanner tests."""

from datetime import datetime
import mock
import unittest

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner.scanners.base_scanner import BaseScanner
from tests.unittest_utils import ForsetiTestCase


class BaseScannerTest(ForsetiTestCase):

    def setUp(self):
        self.fake_utcnow = datetime(
            year=1900, month=11, day=12, hour=13, minute=14, second=15,
            microsecond=16)

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.base_scanner.date_time',
        autospec=True)
    def test_init_scanner_index_id(self, mock_date_time):
        """Test that the 'scanner_index_id' is initialized correctly."""
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow

        expected = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_MICROS)

        BaseScanner.init_scanner_index_id()
        self.assertEquals(expected, BaseScanner.scanner_index_id)


if __name__ == '__main__':
    unittest.main()
