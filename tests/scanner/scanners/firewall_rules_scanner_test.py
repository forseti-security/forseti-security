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
import os
import parameterized

import tests.unittest_utils
from google.cloud.security.common.gcp_type import folder
from google.cloud.security.common.gcp_type import organization
from google.cloud.security.common.gcp_type import project
from google.cloud.security.scanner.scanners import firewall_rules_scanner
from google.cloud.security.scanner.audit import firewall_rules_engine as fre
from tests import unittest_utils


class FirewallRulesScannerTest(unittest_utils.ForsetiTestCase):

    @mock.patch(
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.firewall_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        mre = mock.patch(
            'google.cloud.security.scanner.scanners.firewall_rules_scanner.'
            'firewall_rules_engine').start()
        self.mock_org_rel_dao = mock.patch(
                        'google.cloud.security.common.data_access.'
                        'org_resource_rel_dao.OrgResourceRelDao').start()
        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)
        self.fake_scanner_configs = {'output_path': '/fake/output/path'}
        rules_local_path = unittest_utils.get_datafile_path(os.path.join(
            os.path.dirname( __file__), 'audit'), 'firewall_test_rules.yaml')
        self.scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, '', rules_local_path)
        self.mock_rules_engine = mre
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
        self.project4 = fre.resource_util.create_resource(
            resource_id='test_project_2', resource_type='project')
        self.project_resource_map = {
            'test_project': self.project0,
            'project1': self.project1,
            'project2': self.project2,
            'project3': self.project3,
            'test_project_2': self.project4,
            'honeypot_exception': self.exception,
        }
        self.ancestry = {
            self.project0: [self.folder1, self.org],
            self.project1: [self.folder2, self.org],
            self.project2: [self.folder4, self.folder3, self.org],
            self.project3: [self.folder3, self.org],
            self.project4: [self.folder3, self.org],
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
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.notifier',
        autospec=True)
    @mock.patch.object(
        firewall_rules_scanner.FirewallPolicyScanner,
        '_upload_csv', autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.os',
        autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.datetime',
        autospec=True)
    @mock.patch.object(
        firewall_rules_scanner.csv_writer,
        'write_csv', autospec=True)
    @mock.patch.object(
        firewall_rules_scanner.FirewallPolicyScanner,
        '_output_results_to_db', autospec=True)
    def test_output_results_local_no_email(
        self, mock_output_results_to_db,
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
        rule_indices = {
            'rule1': 1,
            'rule2': 2,
        }
        self.scanner.rules_engine.rule_book.rule_indices.get.side_effect = (
            lambda x, y: rule_indices.get(x, -1))
        violations = [
            firewall_rules_scanner.firewall_rules_engine.RuleViolation(
                resource_type='firewall_rule',
                resource_id='p1',
                rule_id='rule1',
                violation_type='violation1',
                policy_names=['n1'],
                recommended_actions=['a1'],
            ),
            firewall_rules_scanner.firewall_rules_engine.RuleViolation(
                resource_type='firewall_rule',
                resource_id='p2',
                rule_id='rule2',
                violation_type='violation2',
                policy_names=['n2'],
                recommended_actions=['a2'],
            ),
        ]
        flattened_violations = [
            {
                'resource_id': v.resource_id,
                'resource_type': v.resource_type,
                'rule_name': v.rule_id,
                'rule_index': i+1,
                'violation_type': v.violation_type,
                'violation_data': {
                    'policy_names': v.policy_names,
                    'recommended_actions': v.recommended_actions,
                },
            } for i, v in enumerate(violations)]

        self.scanner._output_results(violations, '88888')

        mock_output_results_to_db.assert_called_once_with(
            self.scanner, flattened_violations)
        mock_write_csv.assert_called_once_with(
            resource_name='violations',
            data=flattened_violations,
            write_header=True)
        mock_upload_csv.assert_called_once_with(
            self.scanner,
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        self.assertEquals(0, mock_notifier.process.call_count)

    @mock.patch(
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.notifier',
        autospec=True)
    @mock.patch.object(
        firewall_rules_scanner.FirewallPolicyScanner,
        '_upload_csv', autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.os',
        autospec=True)
    @mock.patch(
        'google.cloud.security.scanner.scanners.firewall_rules_scanner.datetime',
        autospec=True)
    @mock.patch.object(
        firewall_rules_scanner.csv_writer,
        'write_csv', autospec=True)
    @mock.patch.object(
        firewall_rules_scanner.FirewallPolicyScanner,
        '_output_results_to_db', autospec=True)
    def test_output_results_gcs_email(
        self, mock_output_results_to_db,
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
        violations = [
            firewall_rules_scanner.firewall_rules_engine.RuleViolation(
                resource_type='firewall_rule',
                resource_id='p1',
                rule_id='rule1',
                violation_type='violation1',
                policy_names=['n1'],
                recommended_actions=['a1'],
            ),
            firewall_rules_scanner.firewall_rules_engine.RuleViolation(
                resource_type='firewall_rule',
                resource_id='p2',
                rule_id='rule2',
                violation_type='violation2',
                policy_names=['n2'],
                recommended_actions=['a2'],
            ),
        ]
        rule_indices = {
            'rule1': 1,
            'rule2': 2,
        }
        self.scanner.rules_engine.rule_book.rule_indices.get.side_effect = (
            lambda x, y: rule_indices.get(x, -1))
        self.scanner._output_results(violations, '88888')
        flattened_violations = [
            {
                'resource_id': v.resource_id,
                'resource_type': v.resource_type,
                'rule_name': v.rule_id,
                'rule_index': i+1,
                'violation_type': v.violation_type,
                'violation_data': {
                    'policy_names': v.policy_names,
                    'recommended_actions': v.recommended_actions,
                },
            } for i, v in enumerate(violations)]

        mock_output_results_to_db.assert_called_once_with(
            self.scanner, flattened_violations)
        mock_write_csv.assert_called_once_with(
            resource_name='violations',
            data=flattened_violations,
            write_header=True)
        mock_upload_csv.assert_called_once_with(
            self.scanner,
            self.fake_scanner_configs.get('output_path'),
            self.fake_utcnow,
            fake_csv_name)
        self.assertEquals(1, mock_notifier.process.call_count)
        expected_message = {
            'status': 'scanner_done',
            'payload': {
                'email_description': 'Firewall Rules Scan',
                'email_sender':
                self.scanner.global_configs.get('email_sender'),
                'email_recipient':
                self.scanner.global_configs.get('email_recipient'),
                'sendgrid_api_key':
                self.scanner.global_configs.get('sendgrid_api_key'),
                'output_csv_name': fake_csv_name,
                'output_filename': self.scanner._get_output_filename(
                    self.fake_utcnow),
                'now_utc': self.fake_utcnow,
                'all_violations': flattened_violations,
                'resource_counts': '88888',
                'violation_errors': mock_output_results_to_db(
                    self, flattened_violations),
            }
        }
        mock_notifier.process.assert_called_once_with(expected_message)

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
                    'resource_type': 'firewall_rule',
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
                    'resource_type': 'firewall_rule',
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
        rules_local_path = os.path.join(os.path.dirname(
            os.path.dirname( __file__)), 'audit/data/firewall_test_rules.yaml')
        scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, '', rules_local_path)
        resource = self.project_resource_map[project]
        policy = fre.firewall_rule.FirewallRule.from_dict(
            policy_dict, validate=True)
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        violations = scanner.rules_engine.find_policy_violations(
            resource, [policy])
        expected_violations = [
            fre.RuleViolation(**v) for v in expected_violations_dicts]
        self.assert_rule_violation_lists_equal(expected_violations, violations)

    def test_find_violations_matches_violations(self):
        project = 'test_project_2'
        policy_dicts = [
            {
                'name': 'policy1',
                'direction': 'ingress',
                'targetTags': ['internal'],
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['10.0.0.0/8'],
                'network': 'n1',
            },
            {
                'name': 'deleteme',
                'direction': 'ingress',
                'targetTags': ['tag'],
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['23']}],
                'sourceRanges': ['11.0.0.0/8'],
                'network': 'n3',
            },
        ]
        rules_local_path = os.path.join(os.path.dirname(
            os.path.dirname( __file__)), 'audit/data/firewall_test_rules.yaml')
        scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, '', rules_local_path)
        resource = self.project_resource_map[project]
        policies = []
        for policy in policy_dicts:
          policies.append(fre.firewall_rule.FirewallRule.from_dict(
              policy, validate=True))
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        violations = scanner.rules_engine.find_policy_violations(
            resource, policies)
        expected_violations_dicts = [
                {
                    'resource_type': 'firewall_rule',
                    'resource_id': None,
                    'rule_id': 'golden_policy',
                    'violation_type': 'FIREWALL_MATCHES_VIOLATION',
                    'policy_names': ['policy1', 'deleteme'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['deleteme'],
                        'UPDATE_FIREWALL_RULES': [],
                        'INSERT_FIREWALL_RULES': ['golden_policy: rule 1'],
                    },
                }
        ]
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
            firewall_rules_scanner.firewall_rule_dao, 'FirewallRuleDao').start()
        mock_get_firewall_rules().get_firewall_rules.return_value = (
            fake_firewall_rules)
        rules_local_path = os.path.join(os.path.dirname(
            os.path.dirname( __file__)), 'audit/data/firewall_test_rules.yaml')
        scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, '', rules_local_path)
        results = scanner._retrieve()
        self.assertEqual({'firewall_rule': 3}, results[1])
        self.assertItemsEqual(
            expected.items(), results[0])

    @mock.patch.object(
        firewall_rules_scanner.FirewallPolicyScanner,
        '_output_results_to_db',
        autospec=True)
    def test_run_no_email(self, mock_output_results_to_db):
        resource_and_policies = [
            (
                'test_project',
                {
                    'project': 'test_project',
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
                    'project': 'project1',
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
                    'project': 'honeypot_exception',
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
            policy = fre.firewall_rule.FirewallRule.from_dict(
                policy_dict, project_id=project, validate=True)
            fake_firewall_rules.append(policy)
        mock_get_firewall_rules = mock.patch.object(
            firewall_rules_scanner.firewall_rule_dao, 'FirewallRuleDao').start()
        mock_get_firewall_rules().get_firewall_rules.return_value = (
            fake_firewall_rules)
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        rules_local_path = os.path.join(os.path.dirname(
            os.path.dirname( __file__)), 'audit/data/firewall_test_rules.yaml')
        scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, '', rules_local_path)
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        scanner.run()
        expected_violations = [
            {
                'resource_id': 'test_project',
                'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                'rule_name': 'no_rdp_to_linux',
                'rule_index': 1,
                'resource_type': 'firewall_rule',
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
                'rule_name': 'test_instances_rule',
                'rule_index': 0,
                'resource_type': 'firewall_rule',
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
            scanner, expected_violations)

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k.resource_id)
        sorted(violations, key=lambda k: k.resource_id)
        self.assertItemsEqual(expected, violations)


if __name__ == '__main__':
    unittest.main()
