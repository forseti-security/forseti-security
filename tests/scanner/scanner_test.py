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

import mock
import MySQLdb

from google.apputils import basetest
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors
from google.cloud.security.common.gcp_type import iam_policy
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource
from google.cloud.security.scanner import scanner
from google.cloud.security.scanner.audit import org_rules_engine as ore
from tests.inventory.pipelines.test_data import fake_iam_policies


class ScannerRunnerTest(basetest.TestCase):

    def setUp(self):
        self.fake_timestamp = '123456'
        self.scanner = scanner
        self.scanner.LOGGER = mock.MagicMock()
        self.scanner.FLAGS = mock.MagicMock()
        self.scanner.FLAGS.rules = 'fake/path/to/rules.yaml'
        self.fake_main_argv = []
        self.fake_org_policies = fake_iam_policies.FAKE_ORG_IAM_POLICY_MAP
        self.fake_project_policies = fake_iam_policies.FAKE_PROJECT_IAM_POLICY_MAP

    def test_missing_rules_flag_raises_systemexit(self):
        """Test that missing the `rules` flag raises SystemExit/calls sys.exit()."""
        self.scanner.FLAGS.rules = None
        self.scanner.LOGGER.warn = mock.MagicMock()
        with self.assertRaises(SystemExit):
            self.scanner.main(self.fake_main_argv)

    @mock.patch.object(ore.OrgRulesEngine, 'build_rule_book', autospec=True)
    @mock.patch.object(scanner, '_get_timestamp')
    def test_no_timestamp_raises_systemexit(self, mock_get_timestamp, mock_build_rule_book):
        """Test that no org or project policies raises SystemExit/calls sys.exit()."""
        mock_get_timestamp.return_value = None
        with self.assertRaises(SystemExit):
            self.scanner.main(self.fake_main_argv)
        self.assertEqual(1, mock_build_rule_book.call_count)
        self.scanner.LOGGER.warn.assert_called_with('No snapshot timestamp found. Exiting.')

    @mock.patch.object(ore.OrgRulesEngine, 'build_rule_book')
    @mock.patch.object(scanner, '_get_timestamp')
    @mock.patch.object(scanner, '_get_org_policies')
    @mock.patch.object(scanner, '_get_project_policies')
    def test_no_policies_raises_systemexit(
            self,
            mock_project_policies,
            mock_org_policies,
            mock_get_timestamp,
            mock_build_rule_book):
        """Test that no org or project policies raises SystemExit/calls sys.exit()."""
        mock_get_timestamp.return_value = self.fake_timestamp
        mock_org_policies.return_value = []
        mock_project_policies.return_value = []
        with self.assertRaises(SystemExit):
            self.scanner.main(self.fake_main_argv)
        self.scanner.LOGGER.warn.assert_called_with('No policies found. Exiting.')

    @mock.patch.object(ore.OrgRulesEngine, 'build_rule_book', autospec=True)
    @mock.patch.object(scanner, '_get_timestamp')
    @mock.patch.object(scanner, '_get_org_policies')
    @mock.patch.object(scanner, '_get_project_policies')
    @mock.patch.object(scanner, '_find_violations')
    @mock.patch.object(scanner, '_output_results')
    def test_main_no_violations(self,
            mock_output_results,
            mock_find_violations,
            mock_project_policies,
            mock_org_policies,
            mock_get_timestamp,
            mock_build_rule_book):
        """Test main()."""
        mock_get_timestamp.return_value = self.fake_timestamp
        mock_org_policies.return_value = {'a': 1}
        mock_project_policies.return_value = {'b': 2}
        mock_find_violations.return_value = ['a']
        self.scanner.main(self.fake_main_argv)
        self.assertEqual(1, mock_output_results.call_count)

    def test_find_violations(self):
        """Test that find_violations() is called.

        Setup:
            * Create fake policies.
            * Mock the rules engine's find_policy_violations().

        Expected:
            * RulesEngine.find_policy_violations() called 1x.
            * LOGGER.info called 1x.
            * LOGGER.debug called 4x.
        """
        policies = [
            ('x',
             {'role': 'roles/a', 'members': ['user:a@b.c', 'group:g@h.i']}),
            ('y',
             {'role': 'roles/b', 'members': ['user:p@q.r', 'group:x@y.z']}),
        ]
        mock_rules_eng = mock.MagicMock()
        mock_rules_eng.find_policy_violations.return_value = []

        self.scanner._find_violations(policies, mock_rules_eng)

        calls = [mock.call(policies[0][0], policies[0][1]),
                 mock.call(policies[1][0], policies[1][1])]
        mock_rules_eng.find_policy_violations.assert_has_calls(calls)
        self.assertEquals(1, self.scanner.LOGGER.info.call_count)
        self.assertEquals(4, self.scanner.LOGGER.debug.call_count)

    def test_get_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Setup:
            * Create a fake datetime of 01/01/1900 00:00:00.

        Expected:
            * Scanner output filename matches the format.
        """
        fake_datetime = datetime(
            year=1900, month=1, day=1,
            hour=0, minute=0, second=0, microsecond=0)
        actual = self.scanner._get_output_filename(fake_datetime)
        expected = self.scanner.SCANNER_OUTPUT_CSV_FMT.format('19000101T000000Z')
        self.assertEquals(expected, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp')
    def test_get_timestamp(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.return_value = self.fake_timestamp
        actual = self.scanner._get_timestamp()
        expected = self.fake_timestamp
        self.assertEquals(expected, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp')
    def test_get_timestamp_handles_error(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.side_effect = errors.MySQLError(
            'snapshot_cycles', mock.MagicMock())
        actual = self.scanner._get_timestamp()
        expected = None
        self.assertEquals(expected, actual)
        self.assertEquals(1, self.scanner.LOGGER.error.call_count)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.organization_dao.OrganizationDao.get_org_iam_policies')
    def test_get_org_policies_works(self, mock_get_org_iam, mock_conn):
        """Test that get_org_policies() works."""
        org_policies = [{
            organization.Organization('11111'): {
                'role': 'roles/a',
                'members': ['user:a@b.c', 'group:g@h.i']
            }
        }]
        mock_get_org_iam.return_value = org_policies

        actual = self.scanner._get_org_policies(self.fake_timestamp)
        mock_get_org_iam.assert_called_once_with(
            'organizations', self.fake_timestamp)
        self.assertEqual(org_policies, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.project_dao.ProjectDao.get_project_policies')
    def test_get_project_policies(self, mock_get_proj_iam, mock_conn):
        """Test that get_org_policies() works."""
        proj_policies = [{
            project.Project(project_number='11111', project_id='abc111'): {
                'role': 'roles/a',
                'members': ['user:a@b.c', 'group:g@h.i']
            }
        }]
        mock_get_proj_iam.return_value = proj_policies
        actual = self.scanner._get_project_policies(
            self.fake_timestamp)
        mock_get_proj_iam.assert_called_once_with(
            'projects', self.fake_timestamp)
        self.assertEqual(proj_policies, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp')
    def test_get_timestamp(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.return_value = self.fake_timestamp
        actual = scanner._get_timestamp()
        self.assertEqual(1, mock_get_ss_timestamp.call_count)
        self.assertEqual(self.fake_timestamp, actual)

    @mock.patch.object(MySQLdb, 'connect')
    @mock.patch('google.cloud.security.common.data_access.dao.Dao.get_latest_snapshot_timestamp')
    def test_get_timestamp_db_errors(self, mock_get_ss_timestamp, mock_conn):
        """Test that get_timestamp() works."""
        mock_get_ss_timestamp.side_effect = errors.MySQLError(
            'snapshot_cycles', mock.MagicMock())
        scanner.LOGGER = mock.MagicMock()
        actual = scanner._get_timestamp()
        self.assertEqual(1, scanner.LOGGER.error.call_count)
        self.assertIsNone(actual)

    def test_build_scan_summary(self):
        """Test that the scan summary is built correctly."""
        members = [iam_policy.IamPolicyMember.create_from(u)
            for u in ['user:a@b.c', 'group:g@h.i', 'serviceAccount:x@y.z']
        ]
        all_violations = [
            ore.RuleViolation(
                resource_type='organization',
                resource_id='abc111',
                rule_name='Abc 111',
                rule_index=0,
                violation_type=ore.RULE_VIOLATION_TYPE['whitelist'],
                role='role1',
                members=tuple(members)),
            ore.RuleViolation(
                resource_type='project',
                resource_id='def222',
                rule_name='Def 123',
                rule_index=1,
                violation_type=ore.RULE_VIOLATION_TYPE['blacklist'],
                role='role2',
                members=tuple(members)),
        ]
        total_resources = {
            resource.ResourceType.ORGANIZATION: 1,
            resource.ResourceType.PROJECT: 1,
        }

        actual = self.scanner._build_scan_summary(all_violations, total_resources)

        expected_summaries = {
            resource.ResourceType.ORGANIZATION: {
                'pluralized_resource_type': 'Organizations',
                'total': 1,
                'violations': {
                    'abc111': len(members)
                }
            },
            resource.ResourceType.PROJECT: {
                'pluralized_resource_type': 'Projects',
                'total': 1,
                'violations': {
                    'def222': len(members)
                }
            },
        }
        expected_totals = sum(
            [v for t in expected_summaries.values()
            for v in t['violations'].values()])
        expected = (expected_totals, expected_summaries)

        self.assertEqual(expected, actual)
            

if __name__ == '__main__':
    basetest.main()
