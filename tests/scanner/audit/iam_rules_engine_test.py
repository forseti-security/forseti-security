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

"""Tests the IamRulesEngine."""

import copy
import itertools
import json
import mock
import yaml
import unittest

from google.cloud.forseti.common.gcp_type.billing_account import BillingAccount
from google.cloud.forseti.common.gcp_type.bucket import Bucket
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.iam_policy import IamPolicyBinding
from google.cloud.forseti.common.gcp_type.iam_policy import IamPolicyMember
from google.cloud.forseti.common.gcp_type import iam_policy
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import iam_rules_engine as ire
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.scanner.audit.data import test_rules
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path


class IamRulesEngineTest(ForsetiTestCase):
    """Tests for the IamRulesEngine."""

    def setUp(self):
        """Set up."""
        self.fake_timestamp = '12345'

        self.org789 = Organization(
            '778899',
            display_name='My org',
            full_name='fake_org_full_name111',
            data='fake_org_data111')

        self.billing_acct1 = BillingAccount(
            '000000-111111-222222',
            display_name='My billing account',
            parent=self.org789,
            full_name='fake_billing_acct_full_name111',
            data='fake_billing_acct_data111')

        self.billing_acct2 = BillingAccount(
            '999999-AAAAAA-BBBBBB',
            display_name='Another billing account',
            parent=self.org789,
            full_name='fake_billing_acct_full_name222',
            data='fake_billing_acct_data222')

        self.project1 = Project(
            'my-project-1',
            project_number=12345,
            display_name='My project 1',
            parent=self.org789,
            full_name='fake_project_full_name111',
            data='fake_project_data111')

        self.project2 = Project(
            'my-project-2',
            project_number=12346,
            display_name='My project 2',
            full_name='fake_project_full_name222',
            data='fake_project_data222')

        self.folder1 = Folder(
            '333',
            display_name='Folder 1',
            parent=self.org789,
            full_name='fake_folder_full_name111',
            data='fake_folder_data111')

        self.project3 = Project(
            'my-project-3',
            project_number=12347,
            display_name='My project 3',
            parent=self.folder1,
            full_name='fake_project_full_name333',
            data='fake_project_data333')

        self.mock_org_policy_resource = mock.MagicMock()
        self.mock_org_policy_resource.full_name = (
            'organization/778899/')

        self.mock_billing_acct1_policy_resource = mock.MagicMock()
        self.mock_billing_acct1_policy_resource.full_name = (
            'organization/778899/billing_account/000000-111111-222222/')

        self.mock_billing_acct2_policy_resource = mock.MagicMock()
        self.mock_billing_acct2_policy_resource.full_name = (
            'organization/778899/billing_account/999999-AAAAAA-BBBBBB/')

        self.mock_folder1_policy_resource = mock.MagicMock()
        self.mock_folder1_policy_resource.full_name = (
            'organization/778899/folder/333/')

        self.mock_project1_policy_resource = mock.MagicMock()
        self.mock_project1_policy_resource.full_name = (
            'organization/778899/project/project1/my-project-1')

        self.mock_project2_policy_resource = mock.MagicMock()
        self.mock_project2_policy_resource.full_name = (
            'project2/my-project-2')

        self.mock_project3_policy_resource = mock.MagicMock()
        self.mock_project3_policy_resource.full_name = (
            'organization/778899/folder/333/project/my-project-3')

        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.proj_2 = Project(
            'proj-2',
            project_number=22346,
            display_name='My project 2',
            parent=self.org_234,
            full_name='organization/234/project/proj-2/',
            data='fake_project_data_222')

        self.bucket_2_1 = Bucket(
            'internal-2',
            display_name='My project 2, internal data',
            parent=self.proj_2,
            full_name='organization/234/project/proj-2/bucket/internal-2/',
            data='fake_project_data_222_bucket_1')

        self.bucket_2_1_policy_resource = mock.MagicMock()
        self.bucket_2_1_policy_resource.full_name = (
            'organization/234/folder/333/project/proj-2/bucket/internal-2/iam_policy/bucket:internal-2')

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_from_local_json_file_works(self):
        """Test that a RuleBook is built correctly with a json file."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.json')
        rules_engine = ire.IamRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    @mock.patch.object(file_loader,
                       '_read_file_from_gcs', autospec=True)
    def test_build_rule_book_from_gcs_works(self, mock_load_rules_from_gcs):
        """Test that a RuleBook is built correctly with a mocked gcs file.

        Setup:
            * Create a mocked GCS object from a test yaml file.
            * Get the yaml file content.

        Expected results:
            There are 4 resources that have rules, in the rule book.
        """
        bucket_name = 'bucket-name'
        rules_path = 'input/test_rules_1.yaml'
        full_rules_path = 'gs://{}/{}'.format(bucket_name, rules_path)
        rules_engine = ire.IamRulesEngine(rules_file_path=full_rules_path)

        # Read in the rules file
        file_content = None
        with open(get_datafile_path(__file__, 'test_rules_1.yaml'),
                  'r') as rules_local_file:
            try:
                file_content = yaml.safe_load(rules_local_file)
            except yaml.YAMLError:
                raise

        mock_load_rules_from_gcs.return_value = file_content

        rules_engine.build_rule_book({})
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_resource_type_fails(self):
        """Test that a rule without a resource type cannot be created."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_2.yaml')
        rules_engine = ire.IamRulesEngine(rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book({})

    def test_add_single_rule_builds_correct_map(self):
        """Test that adding a single rule builds the correct map."""
        rule_book = ire.IamRuleBook(
            {}, test_rules.RULES1, self.fake_timestamp)
        actual_rules = rule_book.resource_rules_map

        # expected
        rule_bindings = [{
            'role': 'roles/*', 'members': ['user:*@company.com']
        }]
        rule = scanner_rules.Rule('my rule', 0,
            [IamPolicyBinding.create_from(b) for b in rule_bindings],
            mode='whitelist')
        expected_org_rules = ire.ResourceRules(self.org789,
                                               rules=set([rule]),
                                               applies_to='self_and_children')
        expected_proj1_rules = ire.ResourceRules(self.project1,
                                                 rules=set([rule]),
                                                 applies_to='self')
        expected_proj2_rules = ire.ResourceRules(self.project2,
                                                 rules=set([rule]),
                                                 applies_to='self')
        expected_rules = {
            (self.org789, 'self_and_children'): expected_org_rules,
            (self.project1, 'self'): expected_proj1_rules,
            (self.project2, 'self'): expected_proj2_rules
        }

        self.assertEqual(expected_rules, actual_rules)

    def test_invalid_rule_mode_raises_when_verify_mode(self):
        """Test that an invalid rule mode raises error."""
        with self.assertRaises(InvalidRulesSchemaError):
            scanner_rules.RuleMode.verify('nonexistent mode')

    def test_invalid_rule_mode_raises_when_create_rule(self):
        """Test that creating a Rule with invalid rule mode raises error."""
        with self.assertRaises(InvalidRulesSchemaError):
            scanner_rules.Rule('exception', 0, [])

    def test_policy_binding_matches_whitelist_rules(self):
        """Test that a policy binding matches the whitelist rules.

        Setup:
            * Create a test policy binding.
            * Create a test rule binding.
            * Create a whitelist rule with the test rules.

        Expected results:
            All policy binding members are in the whitelist.
        """
        test_binding = [IamPolicyBinding.create_from({
            'role': 'roles/owner',
            'members': [
                'user:foo@company.com',
                'user:abc@def.somewhere.com',
                'group:some-group@googlegroups.com',
                'serviceAccount:12345@iam.gserviceaccount.com',
            ]
        })]
        rule_bindings = [
            {
                'role': 'roles/owner',
                'members': [
                    'user:*@company.com',
                    'user:abc@*.somewhere.com',
                    'group:*@googlegroups.com',
                    'serviceAccount:*@*.gserviceaccount.com',
                ]
            }
        ]

        rule = scanner_rules.Rule('test rule', 0,
            [IamPolicyBinding.create_from(b) for b in rule_bindings],
            mode='whitelist')
        resource_rule = ire.ResourceRules(rules=[rule])
        results = list(resource_rule.find_mismatches(
            self.project1, test_binding))

        self.assertEqual(0, len(results))

    def test_policy_binding_does_not_match_blacklist_rules(self):
        """Test that a policy binding does not match the blacklist.

        Setup:
            * Create a test policy binding.
            * Create a test rule binding.
            * Create a blacklist rule with the test rules.

        Expected results:
            No policy bindings found in the blacklist.
        """
        test_binding = [IamPolicyBinding.create_from({
            'role': 'roles/owner',
            'members': [
                'user:someone@notcompany.com',
            ]
        })]
        rule_bindings = [
            {
                'role': 'roles/owner',
                'members': [
                    'user:*@company.com',
                    'user:abc@*.somewhere.com',
                    'group:*@googlegroups.com',
                    'serviceAccount:*@*.gserviceaccount.com',
                ]
            }
        ]

        rule = scanner_rules.Rule('test rule', 0,
            [IamPolicyBinding.create_from(b) for b in rule_bindings],
            mode='blacklist')
        resource_rule = ire.ResourceRules(rules=[rule])
        results = list(resource_rule.find_mismatches(
            self.project1, test_binding))

        self.assertEqual(0, len(results))

    def test_policy_binding_matches_required_rules(self):
        """Test that a required list of members are found in policy binding.

        Setup:
            * Create a test policy binding.
            * Create a test rule binding.
            * Create a required rule with the test rules.

        Expected results:
            All required members are found in the policy.
        """
        test_binding = [IamPolicyBinding.create_from({
            'role': 'roles/owner',
            'members': [
                'user:foo@company.com',
                'user:abc@def.somewhere.com',
                'group:some-group@googlegroups.com',
                'serviceAccount:12345@iam.gserviceaccount.com',
            ]
        })]
        rule_bindings = [
            {
                'role': 'roles/owner',
                'members': [
                    'user:foo@company.com',
                    'user:abc@def.somewhere.com',
                ]
            }
        ]

        rule = scanner_rules.Rule('test rule', 0,
            [IamPolicyBinding.create_from(b) for b in rule_bindings],
            mode='required')
        resource_rule = ire.ResourceRules(rules=[rule])
        results = list(resource_rule.find_mismatches(
            self.project1, test_binding))

        self.assertEqual(0, len(results))

    def test_policy_binding_mismatches_required_rules(self):
        """Test that a required list of members mismatches policy binding.

        Setup:
            * Create a test policy binding.
            * Create a test rule binding.
            * Create a required rule with the test rules.

        Expected results:
            All required members are found in the policy.
        """
        test_binding = [IamPolicyBinding.create_from({
            'role': 'roles/owner',
            'members': [
                'user:foo@company.com.abc',
                'group:some-group@googlegroups.com',
                'serviceAccount:12345@iam.gserviceaccount.com',
            ]
        })]
        rule_bindings = [
            {
                'role': 'roles/owner',
                'members': [
                    'user:foo@company.com',
                    'user:abc@def.somewhere.com',
                ]
            }
        ]

        rule = scanner_rules.Rule('test rule', 0,
            [IamPolicyBinding.create_from(b) for b in rule_bindings],
            mode='required')
        resource_rule = ire.ResourceRules(resource=self.project1)
        resource_rule.rules.add(rule)
        results = list(resource_rule.find_mismatches(
            self.project1, test_binding))

        self.assertEqual(1, len(results))

    def test_one_member_mismatch(self):
        """Test a policy where one member mismatches the whitelist.

        Setup:
            * Create a RulesEngine and add test_rules.RULES1.
            * Create the policy binding.
            * Create the Rule and rule bindings.
            * Create the resource association for the Rule.

        Expected results:
            One policy binding member missing from the whitelist.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES1, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/editor',
                'members': ['user:abc@company.com', 'user:def@goggle.com']
            }]}

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        ))

        # expected
        rule_bindings = [{
            'role': 'roles/*',
            'members': ['user:*@company.com']
        }]
        rule = scanner_rules.Rule('my rule', 0,
            [IamPolicyBinding.create_from(b) for b in rule_bindings],
            mode='whitelist')
        expected_outstanding = {
            'roles/editor': [
                IamPolicyMember.create_from('user:def@goggle.com')
            ]
        }
        expected_violations = set([
            scanner_rules.RuleViolation(
                resource_type=self.project1.type,
                resource_id=self.project1.id,
                full_name=self.project1.full_name,
                rule_name=rule.rule_name,
                rule_index=rule.rule_index,
                role='roles/editor',
                violation_type='IAM_POLICY_VIOLATION',
                members=tuple(expected_outstanding['roles/editor']),
                resource_data=self.project1.data)
        ])

        self.assertEqual(expected_violations, actual_violations)

    def test_no_mismatch(self):
        """Test a policy where no members mismatch the whitelist.

        Setup:
            * Create a RulesEngine and add test_rules.RULES1.
            * Create the policy binding.
            * Create the Rule and rule bindings.
            * Create the resource association for the Rule.

        Expected results:
            No policy binding members missing from the whitelist.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES1, self.fake_timestamp)

        policy = {
            'bindings': [{
              'role': 'roles/editor',
              'members': ['user:abc@company.com', 'user:def@company.com']
            }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        ))

        # expected
        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_with_no_rules_has_no_violations(self):
        """Test a policy against an empty RuleBook.

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, snapshot_timestamp=self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/editor',
                'members': ['user:abc@company.com', 'user:def@company.com']
            }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        ))

        # expected
        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_empty_policy_with_rules_no_violations(self):
        """Test an empty policy against the RulesEngine with rules.

        Setup:
            * Create a RulesEngine.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES1, self.fake_timestamp)

        self.mock_project1_policy_resource.data = json.dumps({})

        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource, [])
        ))

        # expected
        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_whitelist_blacklist_rules_vs_policy_has_violations(self):
        """Test a ruleset with whitelist and blacklist violating rules.

        Setup:
            * Mock find_ancestors().
            * Create a RulesEngine with RULES2 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path, self.fake_timestamp)
        # TODO: mock the rules local path to return RULES2
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES2, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:baduser@company.com',
                        'user:okuser@company.com',
                        'user:otheruser@other.com'
                    ]
                }
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)
        self.mock_project2_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings),
            rules_engine.find_violations(
                self.project2, self.mock_project2_policy_resource,
                rule_bindings)
        ))

        # expected
        expected_outstanding1 = {
            'roles/editor': [
                IamPolicyMember.create_from('user:otheruser@other.com')
            ]
        }
        expected_outstanding2 = {
            'roles/editor': [
                IamPolicyMember.create_from('user:baduser@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='my rule',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding1['roles/editor']),
                resource_data=self.project1.data),
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='my rule',
                resource_type=self.project2.type,
                resource_id=self.project2.id,
                full_name=self.project2.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding1['roles/editor']),
                resource_data=self.project2.data),
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name='my other rule',
                resource_type=self.project2.type,
                resource_id=self.project2.id,
                full_name=self.project2.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding2['roles/editor']),
                resource_data=self.project2.data),
            scanner_rules.RuleViolation(
                rule_index=2,
                rule_name='required rule',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/viewer',
                members=tuple([IamPolicyMember.create_from(
                    'user:project_viewer@company.com')]),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_whitelist_rules_vs_policy_no_violations(self):
        """Test ruleset on an org with whitelist with no rule violations.

        Setup:
            * Create a RulesEngine with RULES1 rule set.
            * Create policy.

        Expected result:
            * Find no rule violations.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES1, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:okuser@company.com',
                    ]
                }
            ]
        }

        self.mock_org_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.org789, self.mock_org_policy_resource, rule_bindings),
        ))

        self.assertItemsEqual(set(), actual_violations)

    def test_org_proj_rules_vs_policy_has_violations(self):
        """Test rules on org and project with whitelist, blacklist, required.

        Test whitelist, blacklist, and required rules against an org that has
        1 blacklist violation and a project that has 1 whitelist violation and
        1 required violation.

        Setup:
            * Create a RulesEngine with RULES3 rule set.
            * Create policy.

        Expected result:
            * Find 3 rule violations.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES3, self.fake_timestamp)

        org_policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:okuser@company.com',
                        'user:baduser@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])

        project_policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:okuserr2@company.com',
                        'user:user@other.com',
                    ]
                }
            ]
        }
        project_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in project_policy.get('bindings')])

        self.mock_org_policy_resource.data = json.dumps(org_policy)
        self.mock_project1_policy_resource.data = json.dumps(project_policy)

        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.org789, self.mock_org_policy_resource, org_bindings),
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                project_bindings)
        ))

        # expected
        expected_outstanding_org = {
            'roles/editor': [
                IamPolicyMember.create_from('user:baduser@company.com')
            ]
        }
        expected_outstanding_project = {
            'roles/editor': [
                IamPolicyMember.create_from('user:user@other.com')
            ],
            'roles/viewer': [
                IamPolicyMember.create_from('user:project_viewer@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name='my blacklist rule',
                resource_id=self.org789.id,
                resource_type=self.org789.type,
                full_name=self.org789.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=org_policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_org['roles/editor']),
                resource_data=self.org789.data),
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='my whitelist rule',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=project_policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_project['roles/editor']),
                resource_data=self.project1.data),
            scanner_rules.RuleViolation(
                rule_index=2,
                rule_name='my required rule',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/viewer',
                members=tuple(expected_outstanding_project['roles/viewer']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_self_rules_work_with_org_child_rules(self):
        """Test org "self" whitelist works with org "children" whitelist

        Test hierarchical rules.

        Setup:
            * Create a RulesEngine with RULES4 rule set.
            * Create policy.

        Expected result:
            * Find 3 rule violations.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES4, self.fake_timestamp)

        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                        'user:baduser@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])

        project_policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:okuser2@company.com',
                        'user:user@other.com',
                    ]
                }
            ]
        }
        project_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in project_policy.get('bindings')])

        self.mock_org_policy_resource.data = json.dumps(org_policy)
        self.mock_project1_policy_resource.data = json.dumps(project_policy)

        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.org789, self.mock_org_policy_resource, org_bindings),
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                project_bindings)
        ))

        # expected
        expected_outstanding_org = {
            'roles/owner': [
                IamPolicyMember.create_from('user:baduser@company.com')
            ]
        }
        expected_outstanding_proj = {
            'roles/editor': [
                IamPolicyMember.create_from('user:user@other.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='org whitelist',
                resource_id=self.org789.id,
                resource_type=self.org789.type,
                full_name=self.org789.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=org_policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_org['roles/owner']),
                resource_data=self.org789.data),
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name='project whitelist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=project_policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/editor']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_project_noinherit_project_overrides_org_rule(self):
        """Test org with blacklist and child with whitelist, no inherit.

        Test that the project whitelist rule overrides the org blacklist rule
        when the project does not inherit from parent.

        Setup:
            * Create a RulesEngine with RULES5 rule set.
            * Create policy.

        Expected result:
            * Find 0 rule violations.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES5, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        )

        expected_violations = set([])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_2_child_rules_report_violation(self):
        """Test org "children" whitelist works with org "children" blacklist.

        Test that org children whitelist with org children blacklist rules
        report violation.

        Setup:
            * Create a RulesEngine with RULES6 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES6, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        )

        # expected
        expected_outstanding_proj = {
            'roles/owner': [
                IamPolicyMember.create_from('user:owner@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name='project blacklist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_project_inherit_org_rule_violation(self):
        """Test org with blacklist and child with whitelist, no inherit.

        Test that the project whitelist rule overrides the org blacklist rule
        when the project does not inherit from parent.

        Setup:
            * Create a RulesEngine with RULES5 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules5 = copy.deepcopy(test_rules.RULES5)
        rules5['rules'][1]['inherit_from_parents'] = True
        rules_engine.rule_book = ire.IamRuleBook(
            {}, rules5, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        )

        # expected
        expected_outstanding_proj = {
            'roles/owner': [
                IamPolicyMember.create_from('user:owner@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='org blacklist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_self_bl_proj_noinherit_wl_no_violation(self):
        """Test proj policy doesn't violate rule b/l user (org), w/l (project).

        Test that an org with a blacklist on the org level plus a project
        whitelist with no rule inheritance allows the user blacklisted by
        the org, on the project level.

        Setup:
            * Create a RulesEngine with RULES5 rule set.
            * Tweak the rules to make the org blacklist apply to "self".
            * Create policy.

        Expected result:
            * Find 0 rule violations.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules5 = copy.deepcopy(test_rules.RULES5)
        rules5['rules'][0]['resource'][0]['applies_to'] = 'self'
        rules_engine.rule_book = ire.IamRuleBook(
            {}, rules5, self.fake_timestamp)

        policy = {
            'bindings': [{
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        )

        expected_violations = set([])
        self.assertItemsEqual(expected_violations, actual_violations)

    def test_org_self_wl_proj_noinherit_bl_has_violation(self):
        """Test org allowing user + proj blacklisting user has violation.

        Test that org children whitelist with org children blacklist rules
        report violation.

        Setup:
            * Create a RulesEngine with RULES6 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules6 = copy.deepcopy(test_rules.RULES6)
        rules6['rules'][0]['resource'][0]['applies_to'] = 'self'
        rules_engine.rule_book = ire.IamRuleBook(
            {}, rules6, self.fake_timestamp)

        org_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        org_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in org_policy.get('bindings')])

        project_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                    ]
                }
            ]
        }
        project_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in project_policy.get('bindings')])

        self.mock_org_policy_resource.data = json.dumps(org_policy)
        self.mock_project1_policy_resource.data = json.dumps(project_policy)

        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.org789, self.mock_org_policy_resource, org_bindings),
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                project_bindings)
        ))

        # expected
        expected_outstanding_proj = {
            'roles/owner': [
                IamPolicyMember.create_from('user:owner@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name='project blacklist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=project_policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_ignore_case_works(self):
        """Test blacklisted user with different case still violates rule.

        Test that a project's user with a multi-case identifier still
        violates the blacklist.

        Setup:
            * Create a RulesEngine with RULES6 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES6, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:OWNER@company.com',
                    ]
                }
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        )

        # expected
        expected_outstanding_proj = {
            'roles/owner': [
                IamPolicyMember.create_from('user:OWNER@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name='project blacklist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_wildcard_resource_rules_work(self):
        """Test whitelisted wildcard resources.

        Setup:
            * Create a RulesEngine with RULES8 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES8, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                        'user:someone@notcompany.com',
                    ]
                }
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings))

        # expected
        expected_outstanding_proj = {
            'roles/owner': [
                IamPolicyMember.create_from('user:someone@notcompany.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='org whitelist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_wildcard_resources_with_project_whitelist(self):
        """Test whitelisted wildcard resources.

        Setup:
            * Create a RulesEngine with RULES9 rule set.
            * Create policy.

        Expected result:
            * Find 2 rule violations:
               - A policy binding that violates the org whitelist.
               - A policy binding that violates the org whitelist, even though
                 the project whitelist allows it.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES9, self.fake_timestamp)

        policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:owner@company.com',
                        'user:someone@notcompany.com',
                        'user:person@contract-company.com',
                    ]
                },
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:person@contract-company.com',
                    ]
                },
            ]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)

        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(
            rules_engine.find_violations(
                self.project1, self.mock_project1_policy_resource,
                rule_bindings)
        )

        # expected
        # someone@notcompany.com not in any whitelists
        # person@contract-company.com is allowed by the project whitelist
        # but we still alert due to the org whitelist.
        expected_outstanding_proj = {
            'roles/owner': [
                IamPolicyMember.create_from('user:someone@notcompany.com'),
                IamPolicyMember.create_from('user:person@contract-company.com'),
            ],
            'roles/editor': [
                IamPolicyMember.create_from('user:person@contract-company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='org whitelist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][0]['role'],
                members=tuple(expected_outstanding_proj['roles/owner']),
                resource_data=self.project1.data),
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='org whitelist',
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=policy['bindings'][1]['role'],
                members=tuple(expected_outstanding_proj['roles/editor']),
                resource_data=self.project1.data),
        ])

        self.assertItemsEqual(expected_violations, actual_violations)

    def test_folder_rule_whitelist(self):
        """Test a simple folder whitelist rule."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.FOLDER_RULES1, self.fake_timestamp)

        # one violation for folder because of organization 778899
        # one violation for project because of project3's parent
        folder_policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:someone@other.com',
                    ]
                }
            ]
        }
        folder_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in folder_policy.get('bindings')])

        project_policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:someone@company.com',
                    ]
                }
            ]
        }
        project_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in project_policy.get('bindings')])

        self.mock_folder1_policy_resource.data = json.dumps(folder_policy)
        self.mock_project1_policy_resource.data = json.dumps(project_policy)

        actual_violations = set(itertools.chain(
                rules_engine.find_violations(
                    self.folder1, self.mock_folder1_policy_resource,
                    folder_bindings),
                rules_engine.find_violations(
                    self.project3, self.mock_project1_policy_resource,
                    project_bindings)
            )
        )

        # expected
        expected_outstanding = {
            'roles/editor': [
                IamPolicyMember.create_from('user:someone@other.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='folder rule 1',
                resource_id=self.folder1.id,
                resource_type=self.folder1.type,
                full_name=self.folder1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role=project_policy['bindings'][0]['role'],
                members=tuple(expected_outstanding['roles/editor']),
                resource_data=self.folder1.data),
        ])
        self.assertItemsEqual(expected_violations, actual_violations)

    def test_project_required(self):
        """Test required rule."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES10, self.fake_timestamp)

        project1_policy = {
            'bindings': [
                {
                    'role': 'roles/owner',
                    'members': [
                        'user:someone@company.com',
                    ]
                },
                {
                    'role': 'roles/viewer',
                    'members': [
                        'user:someone2@company.com',
                    ]
                },
            ]
        }
        project1_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in project1_policy.get('bindings')])

        project2_policy = {
            'bindings': [
                {
                    'role': 'roles/editor',
                    'members': [
                        'user:someone1@company.com',
                    ]
                }
            ]
        }
        project2_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in project2_policy.get('bindings')])

        self.mock_project1_policy_resource.data = json.dumps(project1_policy)
        self.mock_project2_policy_resource.data = json.dumps(project2_policy)

        actual_violations = set(itertools.chain(
                rules_engine.find_violations(
                    self.project1, self.mock_project1_policy_resource,
                    project1_bindings),
                rules_engine.find_violations(
                    self.project2, self.mock_project2_policy_resource,
                    project2_bindings)
            )
        )

        # expected
        expected_outstanding = {
            'roles/owner': [
                IamPolicyMember.create_from('user:*@company.com')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name='project required',
                resource_id=self.project2.id,
                resource_type=self.project2.type,
                full_name=self.project2.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/owner',
                members=tuple(expected_outstanding['roles/owner']),
                resource_data=self.project2.data),
        ])
        self.assertItemsEqual(expected_violations, actual_violations)

    def test_policy_all_projects_must_have_owners_from_domain_type(self):
        """Test a policy where the owner belongs to the required domain.

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES11, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/owner',
                'members': ['user:def@xyz.edu']
            }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)
        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(rules_engine.find_violations(
            self.project1, self.mock_project1_policy_resource, rule_bindings))

        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_all_projects_must_have_owners_from_wildcard_domain_of_user_type(self):
        """Test a policy where the owner belongs to a wildcard domain.

        Test a policy where the owner belongs to the required domain and the
        domain is specified as a wildcard user ('members': ['user:*@xyz.edu'])

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES12, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/owner',
                'members': ['user:def@xyz.edu']
            }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)
        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(rules_engine.find_violations(
            self.project1, self.mock_project1_policy_resource, rule_bindings))

        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_all_projects_must_have_owners_from_domain_type_fail(self):
        """Test a policy where the owner does not belong to a required domain.

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            The user belongs to the wrong domain and this violation is detected.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES11, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/owner',
                'members': ['user:def@abc.edu']
            }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)
        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(rules_engine.find_violations(
            self.project1, self.mock_project1_policy_resource, rule_bindings))

        expected_outstanding = {
            'roles/owner': [
                IamPolicyMember.create_from('domain:xyz.edu')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name=test_rules.RULES11['rules'][0]['name'],
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/owner',
                members=tuple(expected_outstanding['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_all_projects_must_have_owners_from_wildcard_domain_of_user_type_fail(self):
        """Test a policy where the owner does not belongs to a wildcard domain.

        Test a policy where the owner does not belong to the required domain
        and the domain is specified as a wildcard user ('members':
        ['user:*@xyz.edu'])

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            The user belongs to the wrong domain and this violation is detected.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES12, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/owner',
                'members': ['user:def@abc.edu']
            }]
        }

        self.mock_project1_policy_resource.data = json.dumps(policy)
        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(rules_engine.find_violations(
            self.project1, self.mock_project1_policy_resource, rule_bindings))

        expected_outstanding = {
            'roles/owner': [
                IamPolicyMember.create_from('user:*@xyz.edu')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name=test_rules.RULES12['rules'][0]['name'],
                resource_id=self.project1.id,
                resource_type=self.project1.type,
                full_name=self.project1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/owner',
                members=tuple(expected_outstanding['roles/owner']),
                resource_data=self.project1.data),
        ])

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_object_viewer_from_my_domain_direct_success(self):
        """Test a policy where the object viewer belongs to a specific domain.

        Test a bucket policy where the
            * object viewer belongs to the required domain
            * domain is specified as a wildcard user
              ('members': ['user:*@gcs.cloud'])
            * policy is attached to the bucket directly (ancestors have no
              storage relevant policy bindings)

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES13, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/objectViewer',
                'members': ['user:rr@gcs.cloud']
            }]
        }

        self.bucket_2_1_policy_resource.data = json.dumps(policy)
        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(rules_engine.find_violations(
            self.bucket_2_1, self.bucket_2_1_policy_resource, rule_bindings))

        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_object_viewer_from_my_domain_direct_fail(self):
        """Test a policy where the object viewer belongs to a specific domain.

        Test a bucket policy where the
            * object viewer belongs to the required domain
            * domain is specified as a wildcard user
              ('members': ['user:*@gcs.cloud'])
            * policy is attached to the bucket directly (ancestors have no
              storage relevant policy bindings)

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            the user in the bindings belongs to a wrong domain and a violation
            is detected
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES13, self.fake_timestamp)

        policy = {
            'bindings': [{
                'role': 'roles/objectViewer',
                'members': ['user:rr@wrong.domain']
            }]
        }

        self.bucket_2_1_policy_resource.data = json.dumps(policy)
        rule_bindings = filter(None, [ # pylint: disable=bad-builtin
            iam_policy.IamPolicyBinding.create_from(b)
            for b in policy.get('bindings')])
        actual_violations = set(rules_engine.find_violations(
            self.bucket_2_1, self.bucket_2_1_policy_resource, rule_bindings))

        expected_outstanding = {
            'roles/objectViewer': [
                IamPolicyMember.create_from('user:*@gcs.cloud')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name=test_rules.RULES13['rules'][0]['name'],
                resource_id=self.bucket_2_1.id,
                resource_type=self.bucket_2_1.type,
                full_name=self.bucket_2_1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/objectViewer',
                members=tuple(expected_outstanding['roles/objectViewer']),
                resource_data=self.bucket_2_1.data),
        ])

        self.assertEqual(expected_violations, actual_violations)

    def test_billing_account_policy_succeeds(self):
        """Tests policicies applied to a billing account.

        Test a policy where billing roles (inheritied) are applied to
        whitelisted users, and logging roles (not inherited) are applied to
        groups in the domain.

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES14, self.fake_timestamp)

        billing1_policy = {
            'bindings': [{
                'role': 'roles/billing.admin',
                'members': ['user:cfo@xyz.edu']
            }, {
                'role': 'roles/logging.admin',
                'members': ['group:auditors@xyz.edu']
            }]
        }
        billing1_bindings = [
            iam_policy.IamPolicyBinding.create_from(b)
            for b in billing1_policy.get('bindings')]

        # Rule does not apply to billing account 2.
        billing2_policy = {
            'bindings': [{
                'role': 'roles/billing.admin',
                'members': ['user:tester@xyz.edu']
            }, {
                'role': 'roles/logging.admin',
                'members': ['user:tester@xyz.edu']
            }]
        }
        billing2_bindings = [
            iam_policy.IamPolicyBinding.create_from(b)
            for b in billing2_policy.get('bindings')]

        self.mock_billing_acct1_policy_resource.data = json.dumps(
            billing1_policy)
        self.mock_billing_acct2_policy_resource.data = json.dumps(
            billing2_policy)
        actual_violations = set(itertools.chain(
            rules_engine.find_violations(
                self.billing_acct1, self.mock_billing_acct1_policy_resource,
                billing1_bindings),
            rules_engine.find_violations(
                self.billing_acct2, self.mock_billing_acct2_policy_resource,
                billing2_bindings),
        ))

        expected_violations = set()

        self.assertEqual(expected_violations, actual_violations)

    def test_billing_account_policy_whitelist_fails(self):
        """Test a policy where the billing account grants non-whitelisted roles.

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            The user is not whitelisted and this violation is detected.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES14, self.fake_timestamp)

        billing_policy = {
            'bindings': [{
                'role': 'roles/billing.admin',
                'members': ['user:ceo@xyz.edu', 'group:bad_billers@xyz.edu']
            }]
        }
        billing_bindings = [
            iam_policy.IamPolicyBinding.create_from(b)
            for b in billing_policy.get('bindings')]

        self.mock_billing_acct1_policy_resource.data = json.dumps(
            billing_policy)
        actual_violations = set(rules_engine.find_violations(
            self.billing_acct1, self.mock_billing_acct1_policy_resource,
            billing_bindings))

        expected_outstanding = {
            'roles/billing.admin': [
                IamPolicyMember.create_from('group:bad_billers@xyz.edu')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=0,
                rule_name=test_rules.RULES14['rules'][0]['name'],
                resource_id=self.billing_acct1.id,
                resource_type=self.billing_acct1.type,
                full_name=self.billing_acct1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/billing.admin',
                members=tuple(expected_outstanding['roles/billing.admin']),
                resource_data=self.billing_acct1.data),
        ])

        self.assertEqual(expected_violations, actual_violations)

    def test_billing_account_policy_blacklist_fails(self):
        """Test a policy where the billing account grants blacklisted roles.

        Setup:
            * Create a Rules Engine
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            User logging roles are blacklisted and this violation is detected.
        """
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = ire.IamRulesEngine(rules_local_path)
        rules_engine.rule_book = ire.IamRuleBook(
            {}, test_rules.RULES14, self.fake_timestamp)

        billing_policy = {
            'bindings': [{
                'role': 'roles/logging.admin',
                'members': ['user:ceo@xyz.edu']
            }]
        }
        billing_bindings = [
            iam_policy.IamPolicyBinding.create_from(b)
            for b in billing_policy.get('bindings')]

        self.mock_billing_acct1_policy_resource.data = json.dumps(
            billing_policy)
        actual_violations = set(rules_engine.find_violations(
            self.billing_acct1, self.mock_billing_acct1_policy_resource,
            billing_bindings))

        expected_outstanding = {
            'roles/logging.admin': [
                IamPolicyMember.create_from('user:ceo@xyz.edu')
            ]
        }

        expected_violations = set([
            scanner_rules.RuleViolation(
                rule_index=1,
                rule_name=test_rules.RULES14['rules'][1]['name'],
                resource_id=self.billing_acct1.id,
                resource_type=self.billing_acct1.type,
                full_name=self.billing_acct1.full_name,
                violation_type='IAM_POLICY_VIOLATION',
                role='roles/logging.admin',
                members=tuple(expected_outstanding['roles/logging.admin']),
                resource_data=self.billing_acct1.data),
        ])

        self.assertEqual(expected_violations, actual_violations)


if __name__ == '__main__':
    unittest.main()
