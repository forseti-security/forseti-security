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
import unittest
import mock

from tests.unittest_utils import ForsetiTestCase
from tests.scanner.test_data import fake_iam_policies
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.scanner.audit import iam_rules_engine as ire
from google.cloud.forseti.scanner.scanners import iam_rules_scanner as irs


class ScannerRunnerTest(ForsetiTestCase):

    FAKE_global_configs = {
        'db_host': 'foo_host',
        'db_user': 'foo_user',
        'db_name': 'foo_db',
        'email_recipient': 'foo_email_recipient'
    }

    FAKE_SCANNER_CONFIGS = {'output_path': 'foo_output_path'}

    def setUp(self):
        fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)
        self.fake_utcnow = fake_utcnow
        self.fake_utcnow_str = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)
        self.fake_timestamp = '123456'
        self.scanner = scanner
        self.scanner.LOGGER = mock.MagicMock()
        self.scanner.FLAGS = mock.MagicMock()
        self.scanner.FLAGS.rules = 'fake/path/to/rules.yaml'
        self.scanner.FLAGS.list_engines = None
        self.ire = ire
        self.irs = irs

        self.fake_main_argv = []
        self.fake_org_policies = fake_iam_policies.FAKE_ORG_IAM_POLICY_MAP
        self.fake_project_policies = \
            fake_iam_policies.FAKE_PROJECT_IAM_POLICY_MAP


if __name__ == '__main__':
    unittest.main()
