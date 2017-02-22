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

"""Tests the OrgRulesEngine."""

import mock
import yaml

from google.apputils import basetest
from google.cloud.security.common.gcp_type.iam_policy import IamPolicyMember
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.security.scanner.audit.org_rules_engine import OrgRuleBook
from google.cloud.security.scanner.audit.org_rules_engine import OrgRulesEngine
from google.cloud.security.scanner.audit.org_rules_engine import ResourceRules
from google.cloud.security.scanner.audit.org_rules_engine import Rule
from google.cloud.security.scanner.audit.org_rules_engine import RuleMode
from google.cloud.security.scanner.audit.org_rules_engine import RuleViolation
from google.cloud.security.scanner.audit.org_rules_engine import RULE_VIOLATION_TYPE
from tests.unittest_utils import get_datafile_path


class OrgRulesEngineTest(basetest.TestCase):
    """Tests for the OrgRulesEngine."""

    def setUp(self):
        """Set up."""
        self.project1 = Project(
            'my-project-1', 12345, project_name='My project 1')
        self.project2 = Project('my-project-2', 12346, project_name='My project 2')
        self.org789 = Organization('778899', org_name='My org')

        self.RULES1 = {
            'rules': [
                {
                    'name': 'my rule',
                    'mode': 'whitelist',
                    'resource': [
                        {
                            'type': 'organization',
                            'applies_to': 'self_and_children',
                            'resource_ids': [
                                '778899'
                            ]
                        },
                        {
                            'type': 'project',
                            'applies_to': 'self',
                            'resource_ids': [
                                'my-project-1',
                                'my-project-2',
                            ]
                        }
                    ],
                    'inherit_from_parent': False,
                    'bindings': [
                        {
                            'role': 'roles/*',
                            'members': [
                                'user:*@company.com'
                            ]
                        }
                    ]
                }
            ]
        }

        self.RULES2 = {
            'rules': [
                {
                    'name': 'my rule',
                    'mode': 'whitelist',
                    'resource': [
                        {
                            'type': 'organization',
                            'applies_to': 'self_and_children',
                            'resource_ids': [
                                '778899'
                            ]
                        },
                        {
                            'type': 'project',
                            'applies_to': 'self',
                            'resource_ids': [
                                'my-project-1',
                                'my-project-2',
                            ]
                        }
                    ],
                    'inherit_from_parent': False,
                    'bindings': [
                        {
                            'role': 'roles/*',
                            'members': [
                                'user:*@company.com'
                            ]
                        }
                    ]
                },
                {
                    'name': 'my other rule',
                    'mode': 'blacklist',
                    'resource': [
                        {
                            'type': 'project',
                            'applies_to': 'self',
                            'resource_ids': [
                                'my-project-2',
                            ]
                        }
                    ],
                    'inherit_from_parent': False,
                    'bindings': [
                        {
                            'role': 'roles/*',
                            'members': [
                                'user:baduser@company.com'
                            ]
                        }
                    ]
                },
                {
                    'name': 'required rule',
                    'mode': 'required',
                    'resource': [
                        {
                            'type': 'project',
                            'applies_to': 'self',
                            'resource_ids': [
                                'my-project-1',
                            ]
                        }
                    ],
                    'inherit_from_parent': False,
                    'bindings': [
                        {
                            'role': 'roles/viewer',
                            'members': [
                                'user:project_viewer@company.com'
                            ]
                        }
                    ]
                }
            ]
        }

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = OrgRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_from_local_json_file_works(self):
        """Test that a RuleBook is built correctly with a json file."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.json')
        rules_engine = OrgRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    @mock.patch.object(OrgRulesEngine,
                       '_load_rules_from_gcs', autospec=True)
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
        rules_engine = OrgRulesEngine(rules_file_path=full_rules_path)

        # Read in the rules file
        file_content = None
        with open(get_datafile_path(__file__, 'test_rules_1.yaml'),
                  'r') as rules_local_file:
            try:
                file_content = yaml.safe_load(rules_local_file)
            except yaml.YAMLError:
                raise

        mock_load_rules_from_gcs.return_value = file_content

        rules_engine.build_rule_book()
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_resource_type_fails(self):
        """Test that a rule without a resource type cannot be created."""
        rules_local_path = get_datafile_path(__file__, 'test_rules_2.yaml')
        rules_engine = OrgRulesEngine(rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()

    def test_add_single_rule_builds_correct_map(self):
        """Test that adding a single rule builds the correct map."""
        rule_book = OrgRuleBook(self.RULES1)
        actual_rules = rule_book.resource_rules_map

        # expected
        rule_bindings = [{
            'role': 'roles/*', 'members': ['user:*@company.com']
        }]
        rule = Rule('my rule', 0, rule_bindings, mode='whitelist')
        expected_org_rules = ResourceRules(self.org789,
                                           rules=set([rule]),
                                           applies_to='self_and_children')
        expected_proj1_rules = ResourceRules(self.project1,
                                             rules=set([rule]),
                                             applies_to='self')
        expected_proj2_rules = ResourceRules(self.project2,
                                             rules=set([rule]),
                                             applies_to='self')
        expected_rules = {
            self.org789: expected_org_rules,
            self.project1: expected_proj1_rules,
            self.project2: expected_proj2_rules
        }

        self.assertEqual(expected_rules, actual_rules)

    def test_invalid_rule_mode_raises_when_verify_mode(self):
        """Test that an invalid rule mode raises error."""
        with self.assertRaises(InvalidRulesSchemaError):
            RuleMode.verify('nonexistent mode')

    def test_invalid_rule_mode_raises_when_create_rule(self):
        """Test that creating a Rule with invalid rule mode raises error."""
        with self.assertRaises(InvalidRulesSchemaError):
            Rule('exception', 0, [])

    def test_policy_binding_matches_whitelist_rules(self):
        """Test that a policy binding matches the whitelist rules.

        Setup:
            * Create a test policy binding.
            * Create a test rule binding.
            * Create a whitelist rule with the test rules.

        Expected results:
            All policy binding members are in the whitelist.
        """
        test_binding = {
            'role': 'roles/owner',
            'members': [
                'user:foo@company.com',
                'user:abc@def.somewhere.com',
                'group:some-group@googlegroups.com',
                'serviceAccount:12345@iam.gserviceaccount.com',
            ]
        }
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

        rule = Rule('test rule', 0, rule_bindings,
                    mode='whitelist')
        resource_rule = ResourceRules(rules=[rule])
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
        test_binding = {
            'role': 'roles/owner',
            'members': [
                'user:someone@notcompany.com',
            ]
        }
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

        rule = Rule('test rule', 0, rule_bindings,
                    mode='blacklist')
        resource_rule = ResourceRules(rules=[rule])
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
        test_binding = {
            'role': 'roles/owner',
            'members': [
                'user:foo@company.com',
                'user:abc@def.somewhere.com',
                'group:some-group@googlegroups.com',
                'serviceAccount:12345@iam.gserviceaccount.com',
            ]
        }
        rule_bindings = [
            {
                'role': 'roles/owner',
                'members': [
                    'user:foo@company.com',
                    'user:abc@def.somewhere.com',
                ]
            }
        ]

        rule = Rule('test rule', 0, rule_bindings,
                    mode='required')
        resource_rule = ResourceRules(rules=[rule])
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
        test_binding = {
            'role': 'roles/owner',
            'members': [
                'user:foo@company.com.abc',
                'group:some-group@googlegroups.com',
                'serviceAccount:12345@iam.gserviceaccount.com',
            ]
        }
        rule_bindings = [
            {
                'role': 'roles/owner',
                'members': [
                    'user:foo@company.com',
                    'user:abc@def.somewhere.com',
                ]
            }
        ]

        rule = Rule('test rule', 0, rule_bindings,
                    mode='required')
        resource_rule = ResourceRules(resource=self.project1)
        resource_rule.rules.add(rule)
        results = list(resource_rule.find_mismatches(
            self.project1, test_binding))

        self.assertEqual(1, len(results))

    def test_one_member_mismatch(self):
        """Test a policy where one member mismatches the whitelist.

        Setup:
            * Create a RuleBook and add self.RULES1.
            * Create the policy binding.
            * Create the Rule and rule bindings.
            * Create the resource association for the Rule.

        Expected results:
            One policy binding member missing from the whitelist.
        """
        # actual
        rule_book = OrgRuleBook()
        rule_book._add_rules(self.RULES1)
        policy_bindings = [{
            'role': 'roles/editor',
            'members': ['user:abc@company.com', 'user:def@goggle.com']
        }]

        actual_violations = list(rule_book.find_violations(
            self.project1, policy_bindings[0]))

        # expected
        rule_bindings = [{
            'role': 'roles/*',
            'members': ['user:*@company.com']
        }]
        rule = Rule('my rule', 0, rule_bindings, mode='whitelist')
        expected_outstanding = {
            'roles/editor': [
                IamPolicyMember.create_from('user:def@goggle.com')
            ]
        }
        expected_violations = [
            RuleViolation(
                resource_type=self.project1.resource_type,
                resource_id=self.project1.resource_id,
                rule_name=rule.rule_name,
                rule_index=rule.rule_index,
                role='roles/editor',
                violation_type=RULE_VIOLATION_TYPE.get(rule.mode),
                members=expected_outstanding['roles/editor'])
        ]

        self.assertEqual(expected_violations, actual_violations)

    def test_no_mismatch(self):
        """Test a policy where no members mismatch the whitelist.

        Setup:
            * Create a RuleBook and add self.RULES1.
            * Create the policy binding.
            * Create the Rule and rule bindings.
            * Create the resource association for the Rule.

        Expected results:
            No policy binding members missing from the whitelist.
        """
        # actual
        rule_book = OrgRuleBook()
        rule_book._add_rules(self.RULES1)
        policy_bindings = [{
            'role': 'roles/editor',
            'members': ['user:abc@company.com', 'user:def@company.com']
        }]

        actual_violations = list(rule_book.find_violations(
            self.project1, policy_bindings[0]))

        # expected
        expected_violations = []

        self.assertEqual(expected_violations, actual_violations)

    def test_policy_with_no_rules_has_no_violations(self):
        """Test a policy against an empty RuleBook.

        Setup:
            * Create an empty RuleBook.
            * Create the policy bindings.
            * Created expected violations list.

        Expected results:
            No policy violations found.
        """
        # actual
        rule_book = OrgRuleBook()
        policy_bindings = [{
            'role': 'roles/editor',
            'members': ['user:abc@company.com', 'user:def@company.com']
        }]

        actual_violations = rule_book.find_violations(
            self.project1, policy_bindings[0])

        # expected
        expected_violations = []

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
        rules_engine = OrgRulesEngine(rules_local_path)
        rules_engine.rule_book = OrgRuleBook(self.RULES1)

        actual_violations = rules_engine.find_policy_violations(
            self.project1, {})

        # expected
        expected_violations = []

        self.assertEqual(expected_violations, actual_violations)

    def test_whitelist_blacklist_rules_vs_policy_has_violations(self):
        """Test a ruleset with whitelist and blacklist violating rules.

        Setup:
            * Create a RulesEngine with RULES2 rule set.
            * Create policy.

        Expected result:
            * Find 1 rule violation.
        """
        # actual
        rules_local_path = get_datafile_path(__file__, 'test_rules_1.yaml')
        rules_engine = OrgRulesEngine(rules_local_path)
        rules_engine.rule_book = OrgRuleBook(self.RULES2)

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

        actual_violations = []
        actual_violations.extend(rules_engine.find_policy_violations(
            self.project1, policy))
        actual_violations.extend(rules_engine.find_policy_violations(
            self.project2, policy))

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

        expected_violations = [
            RuleViolation(
                rule_index=0,
                rule_name='my rule',
                resource_id=self.project1.resource_id,
                resource_type=self.project1.resource_type,
                violation_type='ADDED',
                role=policy['bindings'][0]['role'],
                members=expected_outstanding1['roles/editor']),
            RuleViolation(
                rule_index=0,
                rule_name='my rule',
                resource_type=self.project2.resource_type,
                resource_id=self.project2.resource_id,
                violation_type='ADDED',
                role=policy['bindings'][0]['role'],
                members=expected_outstanding1['roles/editor']),
            RuleViolation(
                rule_index=1,
                rule_name='my other rule',
                resource_type=self.project2.resource_type,
                resource_id=self.project2.resource_id,
                violation_type='ADDED',
                role=policy['bindings'][0]['role'],
                members=expected_outstanding2['roles/editor']),
            RuleViolation(
                rule_index=2,
                rule_name='required rule',
                resource_id=self.project1.resource_id,
                resource_type=self.project1.resource_type,
                violation_type='REMOVED',
                role='roles/viewer',
                members=[IamPolicyMember.create_from(
                    'user:project_viewer@company.com')])
        ]

        self.assertItemsEqual(expected_violations, actual_violations)


if __name__ == '__main__':
    basetest.main()
