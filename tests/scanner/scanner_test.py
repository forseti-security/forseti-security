# Copyright 2017 Google Inc.
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
import os

import mock
import MySQLdb

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.data_access import violation_dao as vdao
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.gcp_type import project
from google.cloud.security.notifier import notifier
from google.cloud.security.scanner import scanner
from google.cloud.security.scanner.audit import iam_rules_engine as ire
from google.cloud.security.scanner.scanners import iam_rules_scanner as irs
from tests.inventory.pipelines.test_data import fake_iam_policies


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
            scanner.OUTPUT_TIMESTAMP_FMT)
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

    # TODO: Fix this test
    #@mock.patch.object(ire.IamRulesEngine, 'build_rule_book', autospec=True)
    #@mock.patch.object(scanner, '_get_timestamp')
    #def test_no_timestamp_raises_systemexit(self, mock_get_timestamp, mock_build_rule_book):
    #    """Test that no org or project policies raises SystemExit/calls sys.exit()."""
    #    mock_get_timestamp.return_value = None
    #    with self.assertRaises(SystemExit):
    #        self.scanner.main(self.fake_main_argv)
    #    self.assertEqual(1, mock_build_rule_book.call_count)
    #    self.scanner.LOGGER.warn.assert_called_with('No snapshot timestamp found. Exiting.')

    # TODO: Fix this test
    #@mock.patch.object(ire.IamRulesEngine, 'build_rule_book')
    #@mock.patch.object(scanner, '_get_timestamp')
    #@mock.patch.object(irep.LoadIamDataPipeline, '_get_org_policies')
    #@mock.patch.object(irep.LoadIamDataPipeline, '_get_project_policies')
    #def test_no_policies_raises_systemexit(
    #        self,
    #        mock_project_policies,
    #        mock_org_policies,
    #        mock_get_timestamp,
    #        mock_build_rule_book):
    #    """Test that no org or project policies raises SystemExit/calls sys.exit()."""
    #    mock_get_timestamp.return_value = self.fake_timestamp
    #    mock_org_policies.return_value = []
    #    mock_project_policies.return_value = []
    #    with self.assertRaises(SystemExit):
    #        self.scanner.main(self.fake_main_argv)
    #    self.scanner.LOGGER.warn.assert_called_with('No policies found. Exiting.')

    # TODO: Fix this test
    #@mock.patch.object(ire.IamRulesEngine, 'build_rule_book', autospec=True)
    #@mock.patch.object(scanner, '_get_timestamp')
    #@mock.patch.object(scanner, '_get_org_policies')
    #@mock.patch.object(scanner, '_get_project_policies')
    #@mock.patch.object(irep.LoadIamDataPipeline, 'find_violations')
    #@mock.patch.object(scanner, '_output_results')
    #def test_main_no_violations(self,
    #        mock_output_results,
    #        mock_find_violations,
    #        mock_project_policies,
    #        mock_org_policies,
    #        mock_get_timestamp,
    #        mock_build_rule_book):
    #    """Test main()."""
    #    mock_get_timestamp.return_value = self.fake_timestamp
    #    mock_org_policies.return_value = {'a': 1}
    #    mock_project_policies.return_value = {'b': 2}
    #    mock_find_violations.return_value = ['a']
    #    self.scanner.main(self.fake_main_argv)
    #    self.assertEqual(1, mock_output_results.call_count)

    # TODO: fix this test
    #def test_find_violations(self):
    """Test that find_violations() is called.

        Setup:
            * Create fake policies.
            * Mock the rules engine's find_policy_violations().

        Expected:
            * RulesEngine.find_policy_violations() called 1x.
            * LOGGER.info called 1x.
            * LOGGER.debug called 4x.
        """

    #    policies = [
    #        ('x',
    #         {'role': 'roles/a', 'members': ['user:a@b.c', 'group:g@h.i']}),
    #        ('y',
    #         {'role': 'roles/b', 'members': ['user:p@q.r', 'group:x@y.z']}),
    #    ]
    #    mock_rules_eng = mock.MagicMock()
    #    mock_rules_eng.find_policy_violations.return_value = []

    #    self.irep.LoadIamDataPipeline(self.fake_timestamp).find_violations(policies, mock_rules_eng)

    #    calls = [mock.call(policies[0][0], policies[0][1]),
    #             mock.call(policies[1][0], policies[1][1])]
    #    mock_rules_eng.find_policy_violations.assert_has_calls(calls)
    #    self.assertEquals(1, self.irep.LOGGER.info.call_count)
    #    self.assertEquals(4, self.irep.LOGGER.debug.call_count)

    def test_get_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Expected:
            * Scanner output filename matches the format.
        """
        actual = self.scanner._get_output_filename(self.fake_utcnow)
        expected = self.scanner.SCANNER_OUTPUT_CSV_FMT.format(self.fake_utcnow_str)
        self.assertEquals(expected, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch(
        'google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp'
    )
    def test_get_timestamp(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.return_value = self.fake_timestamp
        actual = self.scanner._get_timestamp(self.FAKE_global_configs)
        expected = self.fake_timestamp
        self.assertEquals(expected, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch(
        'google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp'
    )
    def test_get_timestamp_handles_error(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.side_effect = errors.MySQLError(
            'snapshot_cycles', mock.MagicMock())
        actual = self.scanner._get_timestamp(self.FAKE_global_configs)
        expected = None
        self.assertEquals(expected, actual)
        self.assertEquals(1, self.scanner.LOGGER.error.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch(
        'google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp'
    )
    def test_get_timestamp(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.return_value = self.fake_timestamp
        actual = scanner._get_timestamp(self.FAKE_global_configs)
        self.assertEqual(1, mock_get_ss_timestamp.call_count)
        self.assertEqual(self.fake_timestamp, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch(
        'google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp'
    )
    def test_get_timestamp_db_errors(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.side_effect = errors.MySQLError(
            'snapshot_cycles', mock.MagicMock())
        scanner.LOGGER = mock.MagicMock()
        actual = scanner._get_timestamp(self.FAKE_global_configs)
        self.assertEqual(1, scanner.LOGGER.error.call_count)
        self.assertIsNone(actual)

if __name__ == '__main__':
    unittest.main()
