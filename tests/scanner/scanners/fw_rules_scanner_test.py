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
import parameterized

from tests.unittest_utils import get_datafile_path
from google.cloud.security.common.gcp_type import folder
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.gcp_type import project
from google.cloud.security.scanner.scanners import fw_rules_scanner
from google.cloud.security.scanner.audit import fw_rules_engine as fre
from tests.unittest_utils import ForsetiTestCase


class FwRulesScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.security.scanner.scanners.fw_rules_scanner.fw_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        self.mock_org_rel_dao = mock.patch(
                        'google.cloud.security.common.data_access.'
                        'org_resource_rel_dao.OrgResourceRelDao').start()
        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)
        self.fake_scanner_configs = {'output_path': '/fake/output/path'}
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        self.scanner = fw_rules_scanner.FwPolicyScanner(
            {}, {}, '', rules_local_path)
        self.mock_rules_engine = mock_rules_engine
        self.project0 = fre.resource_util.create_resource(
            resource_id='test_project', resource_type='project')
        self.project1 = fre.resource_util.create_resource(
            resource_id='project1', resource_type='project')
        self.project2 = fre.resource_util.create_resource(
            resource_id='project2', resource_type='project')
        self.project3 = fre.resource_util.create_resource(
            resource_id='project3', resource_type='project')
        self.exception = fre.resource_util.create_resource(
            resource_id='honeypot_exception', resource_type='project')
        self.folder1 = fre.resource_util.create_resource(
            resource_id='folder1', resource_type='folder')
        self.folder2 = fre.resource_util.create_resource(
            resource_id='test_instances', resource_type='folder')
        self.folder3 = fre.resource_util.create_resource(
            resource_id='folder3', resource_type='folder')
        self.folder4 = fre.resource_util.create_resource(
            resource_id='folder4', resource_type='folder')
        self.org = fre.resource_util.create_resource(
            resource_id='org', resource_type='organization')
        self.project_resource_map = {
            'test_project': self.project0,
            'project1': self.project1,
            'project2': self.project2,
            'project3': self.project3,
            'honeypot_exception': self.exception,
        }
        self.ancestry = {
            self.project0: [self.folder1, self.org],
            self.project1: [self.folder2, self.org],
            self.project2: [self.folder4, self.folder3, self.org],
            self.project3: [self.folder3, self.org],
            self.exception: [self.folder3, self.org],
        }

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

    @parameterized.parameterized.expand([
        (
            'test_project',
            {
                'name': 'policy1',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                'sourceRanges': ['0.0.0.0/0'],
                'targetTags': ['linux'],
            },
            [
                {
                    'resource_type': 'firewall_policy',
                    'resource_id': None,
                    'rule_id': 'no_rdp_to_linux',
                    'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1']
                    },
                }
            ],
        ),
        (
            'project1',
            {
                'name': 'policy1',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['11.0.0.1'],
                'targetTags': ['test'],
            },
            [
                {
                    'resource_type': 'firewall_policy',
                    'resource_id': None,
                    'rule_id': 'test_instances_rule',
                    'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1']
                    },
                }
            ],
        ),
        (
            'honeypot_exception',
            {
                'name': 'policy1',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                'sourceRanges': ['0.0.0.0/0'],
                'targetTags': ['linux'],
            },
            [],
        ),
    ])
    def test_find_violations_from_yaml_rule_book(
        self, project, policy_dict, expected_violations_dicts):
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        scanner = fw_rules_scanner.FwPolicyScanner(
            {}, {}, '', rules_local_path)
        resource = self.project_resource_map[project]
        policy = fre.firewall_rule.FirewallRule.from_dict(
            policy_dict, validate=True)
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        violations = scanner.rules_engine.find_policy_violations(
            resource, policy)
        expected_violations = [
            fre.RuleViolation(**v) for v in expected_violations_dicts]
        self.assert_rule_violation_lists_equal(expected_violations, violations)

    def test_retrieve(self):
        resource_and_policies = [
            (
                'test_project',
                {
                    'name': 'policy1',
                    'network': 'network1',
                    'direction': 'ingress',
                    'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                    'sourceRanges': ['0.0.0.0/0'],
                    'targetTags': ['linux'],
                },
            ),
            (
                'project1',
                {
                    'name': 'policy1',
                    'network': 'network1',
                    'direction': 'ingress',
                    'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                    'sourceRanges': ['11.0.0.1'],
                    'targetTags': ['test'],
                },
            ),
            (
                'honeypot_exception',
                {
                    'name': 'policy1',
                    'network': 'network1',
                    'direction': 'ingress',
                    'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                    'sourceRanges': ['0.0.0.0/0'],
                    'targetTags': ['linux'],
                },
            ),
        ]
        fake_firewall_rules = []
        expected = {}
        for project, policy_dict in resource_and_policies:
            resource = self.project_resource_map[project]
            policy = fre.firewall_rule.FirewallRule.from_dict(
                policy_dict, validate=True)
            expected[resource] = policy
            fake_firewall_rules.append((resource, policy))
        mock_get_firewall_rules = mock.patch.object(
            fw_rules_scanner.firewall_rule_dao, 'FirewallRuleDao').start()
        mock_get_firewall_rules().get_firewall_rules.return_value = (
            fake_firewall_rules)
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        scanner = fw_rules_scanner.FwPolicyScanner(
            {}, {}, '', rules_local_path)
        results = scanner._retrieve()
        self.assertEqual(3, results[1])
        self.assertItemsEqual(
            expected.items(), results[0])

    @mock.patch.object(
        fw_rules_scanner.FwPolicyScanner,
        '_output_results_to_db',
        autospec=True)
    def test_run_no_email(self, mock_output_results_to_db):
        resource_and_policies = [
            (
                'test_project',
                {
                    'name': 'policy1',
                    'network': 'network1',
                    'direction': 'ingress',
                    'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                    'sourceRanges': ['0.0.0.0/0'],
                    'targetTags': ['linux'],
                },
            ),
            (
                'project1',
                {
                    'name': 'policy2',
                    'network': 'network1',
                    'direction': 'ingress',
                    'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                    'sourceRanges': ['11.0.0.1'],
                    'targetTags': ['test'],
                },
            ),
            (
                'honeypot_exception',
                {
                    'name': 'policy3',
                    'network': 'network1',
                    'direction': 'ingress',
                    'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                    'sourceRanges': ['0.0.0.0/0'],
                    'targetTags': ['linux'],
                },
            ),
        ]
        fake_firewall_rules = []
        for project, policy_dict in resource_and_policies:
            resource = self.project_resource_map[project]
            policy = fre.firewall_rule.FirewallRule.from_dict(
                policy_dict, project_id=project, validate=True)
            fake_firewall_rules.append((resource, policy))
        mock_get_firewall_rules = mock.patch.object(
            fw_rules_scanner.firewall_rule_dao, 'FirewallRuleDao').start()
        mock_get_firewall_rules().get_firewall_rules.return_value = (
            fake_firewall_rules)
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        scanner = fw_rules_scanner.FwPolicyScanner(
            {}, {}, '', rules_local_path)
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        scanner.run()
        expected_violations = [
            {
                'resource_id': 'test_project',
                'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                'rule_id': 'no_rdp_to_linux',
                'resource_type': 'firewall_policy',
                'violation_data': {
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1'],
                    }
                },
            },
            {
                'resource_id': 'project1',
                'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                'rule_id': 'test_instances_rule',
                'resource_type': 'firewall_policy',
                'violation_data': {
                    'policy_names': ['policy2'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy2'],
                    }
                },
            },
        ]
        [sorted(v) for v in expected_violations]
        mock_output_results_to_db.assert_called_once_with(
            scanner, 'violations', expected_violations)

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k.resource_id)
        sorted(violations, key=lambda k: k.resource_id)
        self.assertItemsEqual(expected, violations)


if __name__ == '__main__':
    unittest.main()
