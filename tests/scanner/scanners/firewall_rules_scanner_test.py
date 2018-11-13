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
import json
import mock
import os
import parameterized
import unittest

from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner.scanners import firewall_rules_scanner
from google.cloud.forseti.scanner.audit import firewall_rules_engine as fre
from tests import unittest_utils
from tests.scanner.scanners.data import fake_firewall_rules as fake_data


class FirewallRulesScannerTest(unittest_utils.ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.firewall_rules_scanner.firewall_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        mre = mock.patch(
            'google.cloud.forseti.scanner.scanners.firewall_rules_scanner.'
            'firewall_rules_engine').start()
        self.fake_utcnow = datetime(
            year=1900, month=1, day=1, hour=0, minute=0, second=0,
            microsecond=0)
        self.fake_scanner_configs = {'output_path': '/fake/output/path'}
        rules_local_path = unittest_utils.get_datafile_path(os.path.join(
            os.path.dirname( __file__), 'audit'), 'firewall_test_rules.yaml')
        self.scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, mock.MagicMock(), '', '', rules_local_path)
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

    def testget_output_filename(self):
        """Test that the output filename of the scanner is correct.

        Expected:
            * Scanner output filename matches the format.
        """
        fake_utcnow_str = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        expected = string_formats.SCANNER_OUTPUT_CSV_FMT.format(fake_utcnow_str)
        actual = self.scanner.get_output_filename(self.fake_utcnow)
        self.assertEquals(expected, actual)

    @mock.patch.object(
        firewall_rules_scanner.FirewallPolicyScanner,
        '_output_results_to_db', autospec=True)
    def test_output_results_local(self, mock_output_results_to_db):
        """Test _output_results() flattens results & writes them to db."""
        self.scanner.scanner_configs = self.fake_scanner_configs
        rule_indices = {
            'rule1': 1,
            'rule2': 2,
        }
        self.scanner.rules_engine.rule_book.rule_indices.get.side_effect = (
            lambda x, y: rule_indices.get(x, -1))
        violations = [
            firewall_rules_scanner.firewall_rules_engine.RuleViolation(
                resource_type=resource_mod.ResourceType.FIREWALL_RULE,
                resource_id='p1',
                resource_name='n1',
                full_name='fake_full_name111',
                rule_id='rule1',
                violation_type='violation1',
                policy_names=['n1'],
                recommended_actions=['a1'],
                resource_data='fake_inventory_data111'
            ),
            firewall_rules_scanner.firewall_rules_engine.RuleViolation(
                resource_type=resource_mod.ResourceType.FIREWALL_RULE,
                resource_id='p2',
                resource_name='n2',
                full_name='fake_full_name222',
                rule_id='rule2',
                violation_type='violation2',
                policy_names=['n2'],
                recommended_actions=['a2'],
                resource_data='fake_inventory_data222'
            ),
        ]
        flattened_violations = [
            {
                'resource_id': v.resource_id,
                'resource_type': v.resource_type,
                'resource_name': ','.join(v.policy_names),
                'full_name': v.full_name,
                'rule_name': v.rule_id,
                'rule_index': i+1,
                'violation_type': v.violation_type,
                'violation_data': {
                    'policy_names': v.policy_names,
                    'recommended_actions': v.recommended_actions,
                },
                'resource_data': v.resource_data
            } for i, v in enumerate(violations)]

        self.scanner._output_results(violations)

        mock_output_results_to_db.assert_called_once_with(
            self.scanner, flattened_violations)

    @parameterized.parameterized.expand([
        (
            'test_project',
            {
                'name': 'policy1',
                'full_name': 'fake_full_name000',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                'sourceRanges': ['0.0.0.0/0'],
                'targetTags': ['linux'],
            },
            [
                {
                    'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                    'resource_id': None,
                    'resource_name': 'policy1',
                    'full_name': 'fake_full_name000',
                    'rule_id': 'no_rdp_to_linux',
                    'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1']
                    },
                    'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["1", "3389"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["0.0.0.0/0"], "targetTags": ["linux"]}']
                }
            ],
        ),
        (
            'project1',
            {
                'name': 'policy1',
                'full_name': 'organization/1/folder/test_instances/project/project1/firewall/policy1/',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['11.0.0.1'],
                'targetTags': ['test'],
            },
            [
                {
                    'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                    'resource_id': None,
                    'resource_name': 'policy1',
                    'full_name': 'organization/1/folder/test_instances/project/project1/firewall/policy1/',
                    'rule_id': 'test_instances_rule',
                    'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1']
                    },
                    'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["11.0.0.1"], "targetTags": ["test"]}']
                }
            ],
        ),
        (
            'honeypot_exception',
            {
                'name': 'policy1',
                'full_name': '',
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
            {}, {}, mock.MagicMock(), '',  '', rules_local_path)
        resource = self.project_resource_map[project]
        policy = fre.firewall_rule.FirewallRule.from_dict(
            policy_dict, validate=True)
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        violations = scanner.rules_engine.find_violations(
            resource, [policy])
        expected_violations = [
            fre.RuleViolation(**v) for v in expected_violations_dicts]
        self.assert_rule_violation_lists_equal(expected_violations, violations)

    def test_find_violations_matches_violations(self):
        project = 'test_project_2'
        policy_dicts = [
            {
                'name': 'policy1',
                'full_name': 'fake_full_name111',
                'direction': 'ingress',
                'targetTags': ['internal'],
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['10.0.0.0/8'],
                'network': 'n1',
            },
            {
                'name': 'deleteme',
                'full_name': 'fake_full_name222',
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
            {}, {}, mock.MagicMock(), '', '', rules_local_path)
        resource = self.project_resource_map[project]
        policies = []
        for policy in policy_dicts:
          policies.append(fre.firewall_rule.FirewallRule.from_dict(
              policy, validate=True))
        mock_org_rel_dao = mock.Mock()
        mock_org_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        scanner.rules_engine.rule_book.org_res_rel_dao = mock_org_rel_dao
        violations = scanner.rules_engine.find_violations(
            resource, policies)
        expected_violations_dicts = [
                {
                    'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                    'resource_id': None,
                    'resource_name': 'policy1,deleteme',
                    'full_name': 'fake_full_name111',
                    'rule_id': 'golden_policy',
                    'violation_type': 'FIREWALL_MATCHES_VIOLATION',
                    'policy_names': ['policy1', 'deleteme'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['deleteme'],
                        'UPDATE_FIREWALL_RULES': [],
                        'INSERT_FIREWALL_RULES': ['golden_policy: rule 1'],
                    },
                    'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "policy1", "network": "n1", "sourceRanges": ["10.0.0.0/8"], "targetTags": ["internal"]}', '{"allowed": [{"IPProtocol": "tcp", "ports": ["23"]}], "direction": "INGRESS", "name": "deleteme", "network": "n3", "sourceRanges": ["11.0.0.0/8"], "targetTags": ["tag"]}']
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
        resource_and_policies = [
            ('test_project', fake_data.FAKE_FIREWALL_RULE_FOR_TEST_PROJECT),
            ('project1', fake_data.FAKE_FIREWALL_RULE_FOR_PROJECT1),
        ]
        fake_firewall_rules = []
        expected = {}
        for project, policy_dict in resource_and_policies:
            resource = self.project_resource_map[project]
            policy = fre.firewall_rule.FirewallRule.from_dict(
                policy_dict, validate=True)
            expected[resource] = policy
            fake_firewall_rules.append((resource, policy))
        rules_local_path = os.path.join(os.path.dirname(
            os.path.dirname( __file__)), 'audit/data/firewall_test_rules.yaml')
        mock_resource1 = mock.MagicMock()
        mock_resource1.full_name = ('organization/org/folder/folder1/'
                                    'project/project0/firewall/policy1/')
        mock_resource1.type_name = 'firewall/policy1'
        mock_resource1.name = 'policy1'
        mock_resource1.type = 'firewall'
        mock_resource1.data = json.dumps(
            fake_data.FAKE_FIREWALL_RULE_FOR_TEST_PROJECT)

        mock_resource2 = mock.MagicMock()
        mock_resource2.full_name = ('organization/org/folder/test_instances/'
                                    'project/project1/firewall/policy1/')
        mock_resource2.type_name = 'firewall/policy1'
        mock_resource2.name = 'policy1'
        mock_resource2.type = 'firewall'
        mock_resource2.data = json.dumps(
            fake_data.FAKE_FIREWALL_RULE_FOR_PROJECT1)

        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = [mock_resource1,
                                                      mock_resource2]
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access
        )

        scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, mock_service_config, '', '', rules_local_path)
        results = scanner._retrieve()

        self.assertEqual({resource_mod.ResourceType.FIREWALL_RULE: 2}, results[1])

        _, expected_firewall1 = resource_and_policies[0]
        _, expected_firewall2 = resource_and_policies[1]
        expected_names = [
            expected_firewall1.get('full_name'),
            expected_firewall2.get('full_name')
        ]
        retrieved_names = []
        for _, fws in results[0].items():
          for fw in fws:
            retrieved_names.append(fw.full_name)
        self.assertItemsEqual(expected_names, retrieved_names)

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
        rules_local_path = os.path.join(os.path.dirname(
            os.path.dirname( __file__)), 'audit/data/firewall_test_rules.yaml')
        mock_resource1 = mock.MagicMock()
        mock_resource1.full_name = ('organization/org/folder/test_instances/'
                                    'project/project1/firewall/policy1/')
        mock_resource1.type_name = 'firewall/policy888'
        mock_resource1.name = 'policy1'
        mock_resource1.type = 'firewall'
        mock_resource1.data = json.dumps(
            fake_data.FAKE_FIREWALL_RULE_FOR_PROJECT1)
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = [mock_resource1]
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)

        scanner = firewall_rules_scanner.FirewallPolicyScanner(
            {}, {}, mock_service_config, '', '', rules_local_path)
        scanner.rules_engine.rule_book.org_res_rel_dao = mock.MagicMock()
        scanner.run()
        self.assertEquals(1, mock_output_results_to_db.call_count)

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k.resource_id)
        sorted(violations, key=lambda k: k.resource_id)
        self.assertItemsEqual(expected, violations)


if __name__ == '__main__':
    unittest.main()
