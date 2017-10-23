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
"""Scanner runner script test."""

from datetime import datetime
import mock
import unittest

from tests.unittest_utils import get_datafile_path
from google.cloud.security.common.gcp_type import folder
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.gcp_type import project
from google.cloud.security.scanner.scanners import fw_rules_scanner
from tests.unittest_utils import ForsetiTestCase


class FwRulesScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.fw_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)
        self.fake_scanner_configs = {'output_path': '/fake/output/path'}
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        self.scanner = fw_rules_scanner.FwPolicyScanner(
            {}, {}, '', rules_local_path)

    def test_get_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Expected:
            * Scanner output filename matches the format.
        """
        fake_utcnow_str = self.fake_utcnow.strftime(
            self.scanner.OUTPUT_TIMESTAMP_FMT)

        expected = self.scanner.SCANNER_OUTPUT_CSV_FMT.format(fake_utcnow_str)
        actual = self.scanner._get_output_filename(self.fake_utcnow)
        self.assertEquals(expected, actual)

    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.notifier',
        autospec=True)
    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_upload_csv', autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.os',
        autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.datetime',
        autospec=True)
    @mock.patch.object(
        fw_rules_scanner.csv_writer,
        'write_csv', autospec=True)
    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_output_results_to_db', autospec=True)
    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_flatten_violations')
    # autospec on staticmethod will return noncallable mock
    def test_output_results_local_no_email(
        self, mock_flatten_violations, mock_output_results_to_db,
        mock_write_csv, mock_datetime, mock_os, mock_upload_csv, mock_notifier):
        """Test output results for local output, and don't send email.

        Setup:
            * Create fake csv filename.
            * Create fake file path.
            * Mock the csv file name within the context manager.
            * Mock the timestamp for the email.
            * Mock the file path.

        Expect:
            * _upload_csv() is called once with the fake parameters.
        """
        mock_os.path.abspath.return_value = (
            self.fake_scanner_configs.get('output_path'))
        mock_datetime.utcnow = mock.MagicMock()
        mock_datetime.utcnow.return_value = self.fake_utcnow

        fake_csv_name = 'fake.csv'
        fake_csv_file = type(mock_write_csv.return_value.__enter__.return_value)
        fake_csv_file.name = fake_csv_name

        self.scanner.scanner_configs = self.fake_scanner_configs
        self.scanner._output_results(None, '88888')

        self.assertEquals(1, mock_flatten_violations.call_count)
        self.assertEquals(1, mock_output_results_to_db.call_count)
        self.assertEquals(1, mock_write_csv.call_count)
        mock_upload_csv.assert_called_once_with(
            self.scanner,
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        self.assertEquals(0, mock_notifier.process.call_count)

    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.notifier',
        autospec=True)
    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_upload_csv', autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.os',
        autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.datetime',
        autospec=True)
    @mock.patch.object(
        fw_rules_scanner.csv_writer,
        'write_csv', autospec=True)
    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_output_results_to_db', autospec=True)
    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_flatten_violations')
    # autospec on staticmethod will return noncallable mock
    def test_output_results_gcs_email(
        self, mock_flatten_violations, mock_output_results_to_db,
        mock_write_csv, mock_datetime, mock_os, mock_upload_csv, mock_notifier):

        mock_os.path.abspath.return_value = (
            self.fake_scanner_configs.get('output_path'))
        mock_datetime.utcnow = mock.MagicMock()
        mock_datetime.utcnow.return_value = self.fake_utcnow

        fake_csv_name = 'fake.csv'
        fake_csv_file = type(mock_write_csv.return_value.__enter__.return_value)
        fake_csv_file.name = fake_csv_name

        fake_global_configs = {}
        fake_global_configs['email_recipient'] = 'foo@bar.com'
        self.scanner.global_configs = fake_global_configs
        self.scanner.scanner_configs = self.fake_scanner_configs
        self.scanner._output_results(None, '88888')

        self.assertEquals(1, mock_flatten_violations.call_count)
        self.assertEquals(1, mock_output_results_to_db.call_count)
        self.assertEquals(1, mock_write_csv.call_count)
        mock_upload_csv.assert_called_once_with(
            self.scanner,
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        self.assertEquals(1, mock_notifier.process.call_count)


if __name__ == '__main__':
    unittest.main()
