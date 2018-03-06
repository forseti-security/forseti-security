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
"""Scanner runner script test."""

from datetime import datetime
import mock
import unittest

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner.scanners import base_scanner
from google.cloud.forseti.common.gcp_type.bucket import Bucket
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.scanners import iam_rules_scanner
from tests.unittest_utils import ForsetiTestCase


class IamRulesScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.iam_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):

        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)

        self.fake_scanner_configs = {'output_path': '/fake/output/path'}
        self.scanner = iam_rules_scanner.IamPolicyScanner(
            {}, {}, mock.MagicMock(), '', '', '')
        self._add_ancestor_bindings_test_data()

    def _add_ancestor_bindings_test_data(self):
        """Establishes the hierarchy below.

               +----------------------------> proj_1
               |
               |
               +                                     +-------> bucket_3_1
            org_234 +------> folder_1 +-----> proj_3 |
                                                     +-------> bucket_3_2
               +
               |
               +----------------------------> proj_2 +-------> bucket_2_1
        """
        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.proj_1 = Project(
            'proj-1',
            project_number=22345,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/proj-1/',
            data='fake_project_data_111')

        self.proj_2 = Project(
            'proj-2',
            project_number=22346,
            display_name='My project 2',
            parent=self.org_234,
            full_name='organization/234/project/proj-2/',
            data='fake_project_data_222')

        self.folder_1 = Folder(
            '333',
            display_name='Folder 1',
            parent=self.org_234,
            full_name='organization/234/folder/333/',
            data='fake_folder_data_111')

        self.proj_3 = Project(
            'proj-3',
            project_number=22347,
            display_name='My project 3',
            parent=self.folder_1,
            full_name='organization/234/folder/333/project/proj-3/',
            data='fake_project_data_333')

        self.bucket_3_1 = Bucket(
            'internal-3',
            display_name='My project 3, internal data1',
            parent=self.proj_3,
            full_name='organization/234/folder/333/project/proj-3/bucket/internal-3/',
            data='fake_project_data_333_bucket_1')

        self.bucket_3_2 = Bucket(
            'public-3',
            display_name='My project 3, public data',
            parent=self.proj_3,
            full_name='organization/234/folder/333/project/proj-3/bucket/public-3/',
            data='fake_project_data_333_bucket_2')

        self.bucket_2_1 = Bucket(
            'internal-2',
            display_name='My project 2, internal data',
            parent=self.proj_2,
            full_name='organization/234/project/proj-2/bucket/internal-2/',
            data='fake_project_data_222_bucket_1')

        self.org_234_policy_resource = mock.MagicMock()
        self.org_234_policy_resource.full_name = (
            'organization/234/iam_policy/organization:234/')

        self.folder_1_policy_resource = mock.MagicMock()
        self.folder_1_policy_resource.full_name = (
            'organization/234/folder/333/iam_policy/folder:333/')

        self.proj_1_policy_resource = mock.MagicMock()
        self.proj_1_policy_resource.full_name = (
            'organization/234/project/proj-1/iam_policy/project:proj-1')

        self.proj_2_policy_resource = mock.MagicMock()
        self.proj_2_policy_resource.full_name = (
            'organization/234/project/proj-2/iam_policy/project:proj-2')

        self.proj_3_policy_resource = mock.MagicMock()
        self.proj_3_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-3/iam_policy/project:proj-3')

        self.bucket_3_1_policy_resource = mock.MagicMock()
        self.bucket_3_1_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-3/bucket/internal-3/iam_policy/bucket:internal-3')

        self.bucket_3_2_policy_resource = mock.MagicMock()
        self.bucket_3_2_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-3/bucket/public-3/iam_policy/bucket:public-3')

        self.bucket_2_1_policy_resource = mock.MagicMock()
        self.bucket_2_1_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-2/bucket/internal-2/iam_policy/bucket:internal-2')


    def test_get_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Expected:
            * Scanner output filename matches the format.
        """
        fake_utcnow_str = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        expected = string_formats.SCANNER_OUTPUT_CSV_FMT.format(fake_utcnow_str)
        actual = base_scanner.get_output_filename(self.fake_utcnow)
        self.assertEquals(expected, actual)

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.notifier',
        autospec=True)
    @mock.patch.object(base_scanner,'upload_csv', autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.os',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.date_time',
        autospec=True)
    @mock.patch.object(
        iam_rules_scanner.csv_writer,
        'write_csv', autospec=True)
    @mock.patch.object(
        iam_rules_scanner.IamPolicyScanner,
        '_output_results_to_db', autospec=True)
    @mock.patch.object(
        iam_rules_scanner.IamPolicyScanner,
        '_flatten_violations')
    # autospec on staticmethod will return noncallable mock
    def test_output_results_local_no_email(
        self, mock_flatten_violations, mock_output_results_to_db,
        mock_write_csv, mock_date_time, mock_os, mock_upload_csv,
        mock_notifier):
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
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow

        fake_csv_name = 'fake.csv'
        fake_csv_file = type(mock_write_csv.return_value.__enter__.return_value)
        fake_csv_file.name = fake_csv_name

        self.scanner.scanner_configs = self.fake_scanner_configs
        self.scanner._output_results(None, '88888')

        self.assertEqual(1, mock_flatten_violations.call_count)
        self.assertEqual(1, mock_output_results_to_db.call_count)
        self.assertEqual(1, mock_write_csv.call_count)
        mock_upload_csv.assert_called_once_with(
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        self.assertEqual(0, mock_notifier.process.call_count)

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.notifier',
        autospec=True)
    @mock.patch.object(base_scanner,'upload_csv', autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.os',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.date_time',
        autospec=True)
    @mock.patch.object(iam_rules_scanner.csv_writer, 'write_csv', autospec=True)
    @mock.patch.object(
        iam_rules_scanner.IamPolicyScanner,
        '_output_results_to_db', autospec=True)
    @mock.patch.object(
        iam_rules_scanner.IamPolicyScanner,
        '_flatten_violations')
    # autospec on staticmethod will return noncallable mock
    def test_output_results_gcs_email(
        self, mock_flatten_violations, mock_output_results_to_db,
        mock_write_csv, mock_date_time, mock_os, mock_upload_csv,
        mock_notifier):

        mock_os.path.abspath.return_value = (
            self.fake_scanner_configs.get('output_path'))
        mock_date_time.get_utc_now_datetime= mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow

        fake_csv_name = 'fake.csv'
        fake_csv_file = type(mock_write_csv.return_value.__enter__.return_value)
        fake_csv_file.name = fake_csv_name

        fake_global_configs = {}
        fake_global_configs['email_recipient'] = 'foo@bar.com'
        self.scanner.global_configs = fake_global_configs
        self.scanner.scanner_configs = self.fake_scanner_configs
        self.scanner._output_results(None, '88888')

        self.assertEqual(1, mock_flatten_violations.call_count)
        self.assertEqual(1, mock_output_results_to_db.call_count)
        self.assertEqual(1, mock_write_csv.call_count)
        mock_upload_csv.assert_called_once_with(
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        self.assertEquals(1, mock_notifier.process.call_count)


if __name__ == '__main__':
    unittest.main()
