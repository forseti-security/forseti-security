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

"""Tests the GCS Violations upload notifier."""

import mock
import unittest

from datetime import datetime

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import gcs_violations
from tests.notifier.notifiers.test_data import fake_violations
from tests.unittest_utils import ForsetiTestCase


class GcsViolationsnotifierTest(ForsetiTestCase):
    """Tests for gcs_violations_notifier."""

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

        fake_notifier_conf = {
            'gcs_path': 'gs://blah'
        }

        self.gvp = gcs_violations.GcsViolations(
            'abcd',
            '11111',
            [],
            fake_global_conf,
            {},
            fake_notifier_conf)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.gcs_violations.date_time',
        autospec=True)
    def test_get_output_filename(self, mock_date_time):
        """Test _get_output_filename()."""
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow
        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        actual_filename = self.gvp._get_output_filename()
        self.assertEquals(
            string_formats.VIOLATION_CSV_FMT.format(
                self.gvp.resource, self.gvp.cycle_timestamp,
                expected_timestamp),
            actual_filename)

    @mock.patch(
        'google.cloud.forseti.common.gcp_api.storage.StorageClient',
        autospec=True)
    @mock.patch('tempfile.NamedTemporaryFile')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.os')
    def test_run(self, mock_os, mock_tempfile, mock_storage):
        """Test run()."""
        fake_tmpname = 'tmp_name'
        fake_output_name = 'abc'

        self.gvp._get_output_filename = mock.MagicMock(
            return_value=fake_output_name)
        gcs_path = '{}/{}'.format(
            self.gvp.notification_config['gcs_path'],
            fake_output_name)

        mock_tmp_csv = mock.MagicMock()
        mock_tempfile.return_value = mock_tmp_csv
        mock_tmp_csv.name = fake_tmpname
        mock_tmp_csv.write = mock.MagicMock()

        self.gvp.run()

        mock_tmp_csv.write.assert_called()
        mock_storage.return_value.put_text_file.assert_called_once_with(
            fake_tmpname, gcs_path)

    @mock.patch(
        'google.cloud.forseti.common.gcp_api.storage.StorageClient',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_json(self, mock_write_csv, mock_json_stringify,
        mock_storage):
        """Test run() with json file format."""
        notifier_config = fake_violations.NOTIFIER_CONFIGS_GCS_JSON
        notification_config = notifier_config['resources'][0]['notifiers'][0]['configuration']
        resource = 'policy_violations'
        cycle_timestamp = '2018-03-24T00:49:02.891287'
        mock_json_stringify.return_value = 'test123'
        gvp = gcs_violations.GcsViolations(
            resource,
            cycle_timestamp,
            fake_violations.VIOLATIONS,
            fake_violations.GLOBAL_CONFIGS,
            notifier_config,
            notification_config)

        gvp.run()

        self.assertFalse(mock_write_csv.called)
        self.assertTrue(mock_json_stringify.called)

    @mock.patch(
        'google.cloud.forseti.common.gcp_api.storage.StorageClient',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_csv(self, mock_csv_writer, mock_parser, mock_storage):
        """Test run() with default file format (CSV)."""
        notifier_config = fake_violations.NOTIFIER_CONFIGS_GCS_DEFAULT
        notification_config = notifier_config['resources'][0]['notifiers'][0]['configuration']
        resource = 'policy_violations'
        cycle_timestamp = '2018-03-24T00:49:02.891287'
        gvp = gcs_violations.GcsViolations(
            resource,
            cycle_timestamp,
            fake_violations.VIOLATIONS,
            fake_violations.GLOBAL_CONFIGS,
            notifier_config,
            notification_config)

        gvp.run()

        self.assertTrue(mock_csv_writer.called)
        self.assertFalse(mock_parser.called)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.gcs_violations.LOGGER',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.common.gcp_api.storage.StorageClient',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_invalid_data_format(self, mock_write_csv,
        mock_json_stringify, mock_storage, mock_logger):
        """Test run() with json file format."""
        notifier_config = (
            fake_violations.NOTIFIER_CONFIGS_GCS_INVALID_DATA_FORMAT)
        notification_config = notifier_config['resources'][0]['notifiers'][0]['configuration']
        resource = 'policy_violations'
        cycle_timestamp = '2018-03-24T00:49:02.891287'
        mock_json_stringify.return_value = 'test123'
        gvp = gcs_violations.GcsViolations(
            resource,
            cycle_timestamp,
            fake_violations.VIOLATIONS,
            fake_violations.GLOBAL_CONFIGS,
            notifier_config,
            notification_config)

        gvp.run()

        self.assertFalse(mock_write_csv.called)
        self.assertFalse(mock_json_stringify.called)
        self.assertTrue(mock_logger.error.called)
        self.assertEquals(
            ('GCS upload: invalid data format: %s', 'xxx-invalid'),
            mock_logger.error.call_args[0])


if __name__ == '__main__':
    unittest.main()
