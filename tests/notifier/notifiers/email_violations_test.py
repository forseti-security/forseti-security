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

from google.cloud.forseti.common.util.email import EmailUtil
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import email_violations
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

        self.violations = [
            {'full_name': 'o/5/f/4/f/9/p/be-p1-196611/bucket/be-1-ext/',
             'inventory_data': (
                 '{"bindings": [{"members": ["projectEditor:be-p1-196611", '
                 '"projectOwner:be-p1-196611"], "role": "roles/storage.lega'
                 'cyBucketOwner"}, {"members": ["projectViewer:be-p1-196611'
                 '"], "role": "roles/storage.legacyBucketReader"}], "etag":'
                 '"CAE=", "kind": "storage#policy", "resourceId": "projects'
                 '/_/buckets/be-1-ext"}'),
             'resource_id': 'be-1-ext',
             'resource_type': 'bucket',
             'rule_index': 1,
             'rule_name': 'Allow only service accounts to have access',
             'violation_data': {'full_name': 'o/5/f/4/f/9/p/be-p1-196611/bucket/be-1-ext/',
                                 'member': u'user:abc@example.com',
                                 'role': u'roles/storage.objectAdmin'},
             'violation_type': 'ADDED'},
            {'full_name': 'o/5/f/4/f/9/p/be-p1-196611/bucket/be-1-int/',
             'inventory_data': (
                 '{"bindings": [{"members": ["projectEditor:be-p1-196611", '
                 '"projectOwner:be-p1-196611"], "role": "roles/storage.lega'
                 'cyBucketOwner"}, {"members": ["projectViewer:be-p1-196611'
                 '"], "role": "roles/storage.legacyBucketReader"}], "etag":'
                 '"CAE=", "kind": "storage#policy", "resourceId": "projects'
                 '/_/buckets/be-1-int"}'),
             'resource_id': 'be-1-int',
             'resource_type': 'bucket',
             'rule_index': 1,
             'rule_name': 'Allow only service accounts to have access',
             'violation_data': {'full_name': 'o/5/f/4/f/9/p/be-p1-196611/bucket/be-1-int/',
                                'member': u'user:ab.cd@example.com',
                                'role': u'roles/storage.objectViewer'},
             'violation_type': 'ADDED'}]
        self.expected_attachment_path = os.path.join(
                os.path.dirname(__file__), 'test_data',
                'expected_attachment.csv')
        self.evp_init_args = [
            'policy_violations',
            '2018-03-14T14:49:36.101287',
            self.violations,
            self.fake_global_conf,
            {},
            self.fake_pipeline_conf]

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.email_violations.date_time',
        autospec=True)
    def test_make_attachment(self, mock_date_time):
        """Test _get_output_filename()."""
        mock_date_time.get_utc_now_datetime = mock.MagicMock()
        mock_date_time.get_utc_now_datetime.return_value = self.fake_utcnow
        expected_timestamp = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        evp = email_violations.EmailViolations(*self.evp_init_args)
        attachment = evp._make_attachment()
        self.assertEquals(
            string_formats.VIOLATION_CSV_FMT.format(
                evp.resource, evp.cycle_timestamp, expected_timestamp),
            attachment.filename)

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.email_violations.email',
        autospec=True)
    @mock.patch('google.cloud.forseti.common.data_access.csv_writer.os')
    def test__make_attachment(self, mock_os, mock_mail_util):
        """Test _make_attachment()."""
        mail_util = mock.MagicMock(spec=EmailUtil)
        mock_mail_util.EmailUtil.return_value = mail_util
        evp = email_violations.EmailViolations(*self.evp_init_args)
        evp._make_attachment()
        self.assertTrue(mail_util.create_attachment.called)
        self.assertTrue(
            filecmp.cmp(
                mail_util.create_attachment.call_args[1]['file_location'],
                self.expected_attachment_path, shallow=False))

    @mock.patch(
        'google.cloud.forseti.notifier.notifiers.email_violations.email',
        autospec=True)
    def test_make_attachment_no_temp_files_left(self, mock_mail_util):
        """Test _make_attachment() leaves no temp files behind."""
        mail_util = mock.MagicMock(spec=EmailUtil)
        mock_mail_util.EmailUtil.return_value = mail_util
        evp = email_violations.EmailViolations(*self.evp_init_args)
        evp._make_attachment()
        self.assertTrue(mail_util.create_attachment.called)
        self.assertFalse(
            os.path.exists(
                mail_util.create_attachment.call_args[1]['file_location']))


if __name__ == '__main__':
    unittest.main()
