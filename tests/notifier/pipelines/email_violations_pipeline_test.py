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

import base64
from datetime import datetime
import glob
import mock
import os
import random
import shutil
import unittest

from google.cloud.security.notifier.pipelines import email_violations_pipeline
from tests.unittest_utils import ForsetiTestCase


_ORIGINAL_TMPDIR = os.environ.get('TMPDIR')


def setUpModule():
    """Module level setup: the first import of `tempfile` "freezes" the value
    of `os.environ['TMPDIR']`.
    We thus need to perform this initialization only once and _before_ that
    first import."""
    os.environ['TMPDIR'] = '/tmp/forseti--{}'.format(random.randint(1, 100000))
    os.mkdir(os.environ['TMPDIR'])


def tearDownModule():
    """Module level teardown."""
    shutil.rmtree(os.environ['TMPDIR'], ignore_errors=True)
    if _ORIGINAL_TMPDIR:
        os.environ['TMPDIR'] = _ORIGINAL_TMPDIR
    else:
        del(os.environ['TMPDIR'])


class EmailViolationsPipelineTest(ForsetiTestCase):
    """Tests for email_violations_pipeline."""

    def setUp(self):
        """Setup."""
        fake_global_conf = {
            'db_host': 'x',
            'db_name': 'y',
            'db_user': 'z',
        }

        fake_pipeline_conf = {
            'sender': 'foo.sender@company.com',
            'recipient': 'foo.recipient@company.com',
            'sendgrid_api_key': 'foo_email_key',
        }

        self.gvp = email_violations_pipeline.EmailViolationsPipeline(
            'abcd',
            datetime.strftime(datetime.utcnow(), '%Y%m%dT%H%M%SZ'),
            ['violation: abc', 'violation: def'],
            fake_global_conf,
            {},
            fake_pipeline_conf)

    @mock.patch(
        'google.cloud.security.common.util.email_util.EmailUtil',
        autospec=True)
    def test_make_attachment_cleans_up_tempfile(self, mock_emailutil):
        """Test that we leave no temp files behind."""
        tmp_dir = '{}/*'.format(os.environ['TMPDIR'])
        tmp_files_before = glob.glob(tmp_dir)
        self.gvp.mail_util = mock_emailutil
        self.gvp.run()
        tmp_files_after = glob.glob(tmp_dir)
        self.assertEquals(tmp_files_before, tmp_files_after)

    def test_make_attachment_can_read_tempfile(self):
        """Test that _make_attachment() can read the temp file."""
        violations = '["violation: abc", "violation: def"]'
        attachment = self.gvp._make_attachment()
        decoded_content = base64.b64decode(attachment.content)
        self.assertEquals(violations, decoded_content)


if __name__ == '__main__':
    unittest.main()
