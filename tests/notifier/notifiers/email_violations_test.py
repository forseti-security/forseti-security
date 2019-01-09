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

"""Tests the Email Violations upload notifier."""

import filecmp
import mock
import os
import unittest

from datetime import datetime

# pylint: disable=line-too-long
from google.cloud.forseti.common.util.email.sendgrid_connector import SendgridConnector
from google.cloud.forseti.common.util.email.email_factory import EmailFactory
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import base_notification
from google.cloud.forseti.notifier.notifiers import email_violations
from tests.notifier.notifiers.test_data import fake_violations
from tests.unittest_utils import ForsetiTestCase


class EmailViolationsTest(ForsetiTestCase):
    """Tests for email_violations."""

    def setUp(self):
        """Setup."""
        self.fake_utcnow = datetime(
            year=1901, month=2, day=3, hour=4, minute=5, second=6,
            microsecond=7)

        self.fake_global_conf = {
            'db_host': 'x',
            'db_name': 'y',
            'db_user': 'z',
        }

        self.fake_pipeline_conf = {
            'sendgrid_api_key': 'dsvgig9y0u[puv'
        }

        self.expected_csv_attachment_path = os.path.join(
                os.path.dirname(__file__), 'test_data',
                'expected_attachment.csv')

        self.inventory_index_id = 1526675202480850
        self.evp_init_args = [
            'policy_violations',
            self.inventory_index_id,
            fake_violations.VIOLATIONS['iam_policy_violations'],
            self.fake_global_conf,
            {},
            self.fake_pipeline_conf]

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.base_notification.date_time',
        autospec=True)
    def test_make_attachment_csv_name(self, mock_date_time):
        """Test the CSV attachment name()."""
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow
        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        evp = email_violations.EmailViolations(*self.evp_init_args)
        attachment = evp._make_attachment_csv()
        self.assertEquals(
            string_formats.VIOLATION_CSV_FMT.format(
                evp.resource, evp.inventory_index_id, expected_timestamp),
            attachment.filename)

    @mock.patch.object(EmailFactory, 'get_connector')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.os')
    def test_make_attachment_csv_correctness(self, mock_os, mock_get_connector):
        """Test the CSV file correctness."""
        connector = mock.MagicMock(spec=SendgridConnector)
        mock_get_connector.return_value = connector
        evp = email_violations.EmailViolations(*self.evp_init_args)
        evp._make_attachment_csv()
        self.assertTrue(connector.create_attachment.called)
        test = connector.create_attachment.call_args[1]['file_location']
        self.assertTrue(
            filecmp.cmp(
                connector.create_attachment.call_args[1]['file_location'],
                self.expected_csv_attachment_path, shallow=False))

    @mock.patch.object(EmailFactory, 'get_connector')
    def test_make_attachment_json_no_temp_files_left(self, mock_get_connector):
        """Test _make_attachment_json() leaves no temp files behind."""
        connector = mock.MagicMock(spec=SendgridConnector)
        mock_get_connector.return_value = connector
        evp = email_violations.EmailViolations(*self.evp_init_args)
        evp._make_attachment_json()
        self.assertTrue(connector.create_attachment.called)
        self.assertFalse(
            os.path.exists(
                connector.create_attachment.call_args[1]['file_location']))

    @mock.patch.object(EmailFactory, 'get_connector')
    def test_make_attachment_csv_no_temp_files_left(self, mock_get_connector):
        """Test _make_attachment_csv() leaves no temp files behind."""
        connector = mock.MagicMock(spec=SendgridConnector)
        mock_get_connector.return_value = connector
        evp = email_violations.EmailViolations(*self.evp_init_args)
        evp._make_attachment_csv()
        self.assertTrue(connector.create_attachment.called)
        self.assertFalse(
            os.path.exists(
                connector.create_attachment.call_args[1]['file_location']))

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.email_violations.email_factory',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_invalid_data_format(self, mock_write_csv,
        mock_json_stringify, mock_mail_util):
        """Test run() with invalid data format."""
        notifier_config = (
            fake_violations.NOTIFIER_CONFIGS_EMAIL_INVALID_DATA_FORMAT)
        notification_config = notifier_config['email_connector']
        resource = 'policy_violations'
        cycle_timestamp = '2018-03-24T00:49:02.891287'
        mock_json_stringify.return_value = 'test123'
        evp = email_violations.EmailViolations(
            resource,
            cycle_timestamp,
            fake_violations.VIOLATIONS,
            fake_violations.GLOBAL_CONFIGS,
            notifier_config,
            notification_config)

        evp._get_output_filename = mock.MagicMock()
        evp._make_attachment_csv = mock.MagicMock()
        evp._make_attachment_json = mock.MagicMock()
        with self.assertRaises(base_notification.InvalidDataFormatError):
            evp.run()

        self.assertFalse(evp._get_output_filename.called)
        self.assertFalse(evp._make_attachment_csv.called)
        self.assertFalse(evp._make_attachment_json.called)
        self.assertFalse(mock_write_csv.called)
        self.assertFalse(mock_json_stringify.called)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.email_violations.email_factory',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_json_data_format(self, mock_write_csv,
        mock_json_stringify, mock_email_factory):
        """Test run() with json data format."""
        notifier_config = fake_violations.NOTIFIER_CONFIGS_EMAIL_JSON
        notification_config = notifier_config['email_connector']
        resource = 'policy_violations'
        inventory_index_id = 1514764800123456
        mock_json_stringify.return_value = 'test123'
        evp = email_violations.EmailViolations(
            resource,
            inventory_index_id,
            fake_violations.VIOLATIONS,
            fake_violations.GLOBAL_CONFIGS,
            notifier_config,
            notification_config)

        evp._get_output_filename = mock.MagicMock()
        evp._make_attachment_csv = mock.MagicMock()
        evp.run()

        self.assertTrue(evp._get_output_filename.called)
        self.assertEquals(
            string_formats.VIOLATION_JSON_FMT,
            evp._get_output_filename.call_args[0][0])
        self.assertFalse(evp._make_attachment_csv.called)
        self.assertFalse(mock_write_csv.called)
        self.assertTrue(mock_json_stringify.called)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.email_violations.email_factory',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.util.parser.json_stringify')
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.write_csv')
    def test_run_with_csv_data_format(self, mock_write_csv,
        mock_json_stringify, mock_email_factory):
        """Test run() with json data format."""
        notifier_config = fake_violations.NOTIFIER_CONFIGS_EMAIL_DEFAULT
        notification_config = notifier_config['email_connector']
        resource = 'policy_violations'
        inventory_index_id = 1514764800123456
        mock_json_stringify.return_value = 'test123'

        evp = email_violations.EmailViolations(
            resource,
            inventory_index_id,
            fake_violations.VIOLATIONS,
            fake_violations.GLOBAL_CONFIGS,
            notifier_config,
            notification_config)

        evp._get_output_filename = mock.MagicMock()
        evp._make_attachment_json = mock.MagicMock()
        evp.run()

        self.assertTrue(evp._get_output_filename.called)
        self.assertEquals(
            string_formats.VIOLATION_CSV_FMT,
            evp._get_output_filename.call_args[0][0])
        self.assertFalse(evp._make_attachment_json.called)
        self.assertTrue(mock_write_csv.called)
        self.assertFalse(mock_json_stringify.called)


if __name__ == '__main__':
    unittest.main()
