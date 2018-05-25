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

"""Tests the GCS inventory summary upload notifier."""


import mock
import unittest

from datetime import datetime

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import base_notification
from google.cloud.forseti.notifier.notifiers import inventory_summary
from tests.unittest_utils import ForsetiTestCase


class InventorySummaryTest(ForsetiTestCase):
    """Tests for inventory_summary_notifier."""

    def setUp(self):
        """Setup."""
        ForsetiTestCase.setUp(self)
        self.fake_utcnow = datetime(year=1920, month=5, day=6, hour=7, minute=8)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.inventory_summary.date_time',
        autospec=True)
    def test_get_output_filename(self, mock_date_time):
        """Test_get_output_filename()."""

        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow

        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = {}

        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        notifier = inventory_summary.InventorySummary(mock_service_config,
                                                      'abcd')
        actual_filename = notifier._get_output_filename(
            string_formats.INVENTORY_SUMMARY_CSV_FMT)
        expected_filename = string_formats.INVENTORY_SUMMARY_CSV_FMT.format(
                notifier.inventory_index_id, expected_timestamp)
        self.assertEquals(expected_filename, actual_filename)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.inventory_summary.date_time',
        autospec=True)
    def test_get_output_filename_with_json(self, mock_date_time):
        """Test_get_output_filename()."""
       
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow

        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = {}
        
        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        notifier = inventory_summary.InventorySummary(mock_service_config,
                                                      'abcd')

        actual_filename = notifier._get_output_filename(string_formats.INVENTORY_SUMMARY_JSON_FMT)
        expected_filename = string_formats.INVENTORY_SUMMARY_JSON_FMT.format(
                notifier.inventory_index_id, expected_timestamp)
        self.assertEquals(expected_filename, actual_filename)

    @mock.patch(
        'google.cloud.forseti.common.util.file_uploader.StorageClient',
        autospec=True)
    @mock.patch('tempfile.NamedTemporaryFile')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.os')
    def test_upload_to_gcs_with_csv(self, mock_os, mock_tempfile, mock_storage):
        """Test run()."""
        fake_tmpname = 'tmp_name'
        fake_output_name = 'abc'

        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = {
            'inventory': {'gcs_summary': {'enabled': True,
                                          'data_format': 'csv',
                                          'gcs_path': 'gs://abcd'}}}

        notifier = inventory_summary.InventorySummary(mock_service_config,
                                                      'abcd')
        notifier._get_output_filename = mock.MagicMock(return_value=fake_output_name)

        gcs_path = '{}/{}'.format('gs://abcd', fake_output_name)

        mock_tmp_csv = mock.MagicMock()
        mock_tempfile.return_value = mock_tmp_csv
        mock_tmp_csv.name = fake_tmpname
        mock_tmp_csv.write = mock.MagicMock()

        notifier._upload_to_gcs([{}])

        mock_tmp_csv.write.assert_called()
        mock_storage.return_value.put_text_file.assert_called_once_with(
            fake_tmpname, gcs_path)

    @mock.patch(
        'google.cloud.forseti.common.util.file_uploader.StorageClient',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_json(self, mock_write_csv, mock_json_stringify,
        mock_storage):
        """Test run() with json file format."""
        mock_json_stringify.return_value = 'test123'
        fake_tmpname = 'tmp_name'
        fake_output_name = 'abc'


        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = {
            'inventory': {'gcs_summary': {'enabled': True,
                                          'data_format': 'json',
                                          'gcs_path': 'gs://abcd'}}}

        notifier = inventory_summary.InventorySummary(mock_service_config,
                                                      'abcd')
        notifier._get_output_filename = mock.MagicMock(return_value=fake_output_name)

        notifier._upload_to_gcs([{}])

        self.assertTrue(notifier._get_output_filename.called)
        self.assertEquals(
            string_formats.INVENTORY_SUMMARY_JSON_FMT,
            notifier._get_output_filename.call_args[0][0])
        self.assertFalse(mock_write_csv.called)
        self.assertTrue(mock_json_stringify.called)

    @mock.patch(
        'google.cloud.forseti.common.util.file_uploader.StorageClient',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_invalid_data_format(self, mock_write_csv,
        mock_json_stringify, mock_storage):
        """Test run() with json file format."""

        mock_service_config = mock.MagicMock()
        mock_service_config.get_notifier_config.return_value = {
            'inventory': {'gcs_summary': {'enabled': True,
                                          'data_format': 'blah',
                                          'gcs_path': 'gs://abcd'}}}

        notifier = inventory_summary.InventorySummary(mock_service_config,
                                                      'abcd')
        notifier._get_output_filename = mock.MagicMock()

        with self.assertRaises(base_notification.InvalidDataFormatError):
            notifier._upload_to_gcs([{}])

        self.assertFalse(notifier._get_output_filename.called)
        self.assertFalse(mock_write_csv.called)
        self.assertFalse(mock_json_stringify.called)


if __name__ == '__main__':
    unittest.main()
