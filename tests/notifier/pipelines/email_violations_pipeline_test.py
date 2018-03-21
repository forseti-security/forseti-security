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

"""Tests the Email Violations upload pipeline."""

import mock
import unittest

from datetime import datetime

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.pipelines import email_violations_pipeline
from tests.unittest_utils import ForsetiTestCase


class EmailViolationsPipelineTest(ForsetiTestCase):
    """Tests for email_violations_pipeline."""

    def setUp(self):
        """Setup."""
        self.fake_utcnow = datetime(
            year=1901, month=2, day=3, hour=4, minute=5, second=6,
            microsecond=7)

        fake_global_conf = {
            'db_host': 'x',
            'db_name': 'y',
            'db_user': 'z',
        }

        fake_pipeline_conf = {
            'sendgrid_api_key': 'dsvgig9y0u[puv'
        }

        self.evp = email_violations_pipeline.EmailViolationsPipeline(
            'abcd',
            '11111',
            [],
            fake_global_conf,
            {},
            fake_pipeline_conf)

    @mock.patch(
        'google.cloud.forseti.notifier.pipelines.email_violations_pipeline'
        '.date_time',
        autospec=True)
    def test_get_output_filename(self, mock_date_time):
        """Test _get_output_filename()."""
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow
        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        actual_filename = self.evp._get_output_filename()
        self.assertEquals(
            string_formats.VIOLATION_CSV_FMT.format(
                self.evp.resource, self.evp.cycle_timestamp,
                expected_timestamp),
            actual_filename)


if __name__ == '__main__':
    unittest.main()
