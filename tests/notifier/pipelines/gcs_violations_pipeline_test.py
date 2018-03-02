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

"""Tests the GCS Violations upload pipeline."""

import mock
import unittest

from datetime import datetime

from google.cloud.forseti.scanner.scanners import base_scanner

from google.cloud.forseti.common.util import string_formats, date_time
from google.cloud.forseti.notifier.pipelines import gcs_violations_pipeline
from tests.unittest_utils import ForsetiTestCase


class GcsViolationsPipelineTest(ForsetiTestCase):
    """Tests for gcs_violations_pipeline."""

    def setUp(self):
        """Setup."""
        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)

        fake_global_conf = {
            'db_host': 'x',
            'db_name': 'y',
            'db_user': 'z',
        }

        fake_pipeline_conf = {
            'gcs_path': 'gs://blah'
        }

        self.gvp = gcs_violations_pipeline.GcsViolationsPipeline(
            'abcd',
            '11111',
            [],
            fake_global_conf,
            {},
            fake_pipeline_conf)

    @mock.patch(
        'google.cloud.forseti.notifier.pipelines.gcs_violations_pipeline'
        '.date_time',
        autospec=True)
    def test_get_output_filename(self, mock_date_time):
        """Test _get_output_filename()."""
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow
        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        actual_filename = self.gvp._get_output_filename()
        self.assertEquals(
            string_formats.VIOLATION_JSON_FMT.format(
                self.gvp.resource, self.gvp.cycle_timestamp, expected_timestamp),
            actual_filename)

    @mock.patch(
        'google.cloud.forseti.common.gcp_api.storage.StorageClient',
        autospec=True)
    @mock.patch('tempfile.NamedTemporaryFile')
    def test_run(self, mock_tempfile, mock_storage):
        """Test run()."""
        fake_tmpname = 'tmp_name'
        fake_output_name = 'abc'

        self.gvp._get_output_filename = mock.MagicMock(
            return_value=fake_output_name)
        gcs_path = '{}/{}'.format(
            self.gvp.pipeline_config['gcs_path'],
            fake_output_name)

        mock_tmp_json = mock.MagicMock()
        mock_tempfile.return_value.__enter__.return_value = mock_tmp_json
        mock_tmp_json.name = fake_tmpname
        mock_tmp_json.write = mock.MagicMock()

        self.gvp.run()

        mock_tmp_json.write.assert_called()
        mock_storage.return_value.put_text_file.assert_called_once_with(
            fake_tmpname, gcs_path)


if __name__ == '__main__':
    unittest.main()
