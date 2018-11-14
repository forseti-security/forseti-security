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

"""Tests the CloudSqlRulesEngine."""
# pylint: disable=line-too-long
import unittest
import mock

from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.audit import external_project_access_rules_engine as engine_module
from google.cloud.forseti.scanner.audit import errors as audit_errors
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
# pylint: enable=line-too-long

class ExternalProjectAccessRulesEngineTest(ForsetiTestCase):
    """Tests for the ExternalProjectAccessRulesEngine."""

    TEST_ANCESTRIES = {
        'user1@example.com': [Project('13579'),
                              Folder('24680'),
                              Organization('1234567')],
        'user2@example.com': [Project('13579'),
                              Folder('0987654321'),
                              Organization('1234567')]}
    TEST_ANCESTRIES_SIMPLE = {
        'user1@example.com': [Project('13579'),
                              Organization('567890')]}
    TEST_ANCESTRIES_VIOLATIONS = {
        'user2@example.com': [Project('13579'),
                              Folder('24680'),
                              Organization('1357924680')]}

    def setUp(self):
        self.rules_engine = engine_module
        self.rules_engine.LOGGER = mock.MagicMock()
        self.inventory_config = mock.MagicMock()
        self.inventory_config.get_root_resource_id = (
            mock.MagicMock(return_value='organizations/567890'))


    def test_no_rule_added(self):
        """Test that a RuleBook is built correctly with an empty yaml file."""
        rules_local_path = get_datafile_path(
            __file__, 'external_project_access_test_rules_0.yaml')
        rules_engine = engine_module.ExternalProjectAccessRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        self.assertEqual(0, len(rules_engine.rule_book.resource_rules_map))

    def test_good_yaml_file(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(
            __file__, 'external_project_access_test_rules_1.yaml')
        rules_engine = engine_module.ExternalProjectAccessRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))

    def test_yaml_file_bad_ancestor(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(
            __file__, 'external_project_access_test_rules_2.yaml')
        rules_engine = engine_module.ExternalProjectAccessRulesEngine(
            rules_file_path=rules_local_path)
        with self.assertRaises(audit_errors.InvalidRulesSchemaError):
            rules_engine.build_rule_book(self.inventory_config)

    def test_no_violations(self):
        """Test that no violations are found"""
        all_violations = []
        rules_local_path = get_datafile_path(
            __file__, 'external_project_access_test_rules_1.yaml')
        rules_engine = engine_module.ExternalProjectAccessRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        for user, ancestry in self.TEST_ANCESTRIES.iteritems():
            violations = rules_engine.find_violations(
                user, ancestry, True)
            all_violations.extend(violations)
        self.assertEqual(len(all_violations), 0)

    def test_no_violations_no_rules(self):
        """Test that no violations are found when no rules in the file."""
        all_violations = []
        rules_local_path = get_datafile_path(
            __file__, 'external_project_access_test_rules_0.yaml')
        rules_engine = engine_module.ExternalProjectAccessRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        for user, ancestry in self.TEST_ANCESTRIES_SIMPLE.iteritems():
            violations = rules_engine.find_violations(
                user, ancestry, True)
            all_violations.extend(violations)
        self.assertEqual(len(all_violations), 0)

    def test_violations_are_found(self):
        """Test that violations are found"""
        all_violations = []
        rules_local_path = get_datafile_path(
            __file__, 'external_project_access_test_rules_1.yaml')
        rules_engine = engine_module.ExternalProjectAccessRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book(self.inventory_config)
        for user, ancestry in self.TEST_ANCESTRIES_VIOLATIONS.iteritems():
            violations = rules_engine.find_violations(user, 
                                                             ancestry, 
                                                             True)
            all_violations.extend(violations)
        self.assertEqual(len(all_violations), 2)


class ExternalProjectAccessRuleBookTest(ForsetiTestCase):
    """Tests for the ExternalProjectAccessRuleBook."""

    TEST_GOOD_RULE = dict(name='default',
                          allowed_ancestors=['organizations/7890'])
    TEST_BAD_RULE = dict(name='default',
                         allowed_ancestors=['policy/12345'])
    TEST_RULE_DEFS = dict(rules=[TEST_GOOD_RULE])

    TEST_ANCESTORS = [Project('123'),
                      Folder('456'),
                      Organization('7890')]
    TEST_BAD_ANCESTORS = [Project('123'),
                          Folder('456'),
                          Organization('ABC')]

    def setUp(self):
        """Set up."""
        self.rule_index = 0
        self.rules_engine = engine_module
        self.rules_engine.LOGGER = mock.MagicMock()
        self.inventory_config = mock.MagicMock()

        self.inventory_config.get_root_resource_id = (
            mock.MagicMock(return_value='organizations/7890'))
        self.rule_book = (
            engine_module.ExternalProjectAccessRuleBook(self.inventory_config))

    def test_validate_good_ancestor(self):
        """Test proper rule validation"""
        self.rule_book.validate_ancestors(
            self.TEST_GOOD_RULE['allowed_ancestors'], 0)

    def test_validate_bad_ancestor(self):
        """Test proper rule validation against bad ancestor"""
        with self.assertRaises(audit_errors.InvalidRulesSchemaError):
            self.rule_book.validate_ancestors(
                self.TEST_BAD_RULE['allowed_ancestors'], 0)

    def test_missing_ancestors(self):
        """Test proper rule validation against missing ancestors"""
        with self.assertRaises(audit_errors.InvalidRulesSchemaError):
            self.rule_book.validate_ancestor(None, 0)

    def test_process_good_rule(self):
        """Test proper rule processing"""
        resources = self.rule_book.process_rule(self.TEST_GOOD_RULE, 0)
        self.assertEqual(resources[0].id, '7890')
        self.assertTrue(isinstance(resources[0], Organization))


    def test_process_bad_rule(self):
        """Test proper rule validation with exception"""
        with self.assertRaises(audit_errors.InvalidRulesSchemaError):
            self.rule_book.process_rule(self.TEST_BAD_RULE, 0)

    def test_add_rule(self):
        """Test proper rule addition"""
        self.rule_book.add_rule(self.TEST_GOOD_RULE, 0)
        self.assertEqual(1, len(self.rule_book.resource_rules_map))

    def test_add_rules(self):
        """Test proper addtion of multiple rules"""
        self.rule_book.add_rules(self.TEST_RULE_DEFS)
        self.assertEqual(1, len(self.rule_book.resource_rules_map))

    def test_no_violations(self):
        """Test no violations are found"""
        violations = self.rule_book.find_violations('user@example.com',
                                                           self.TEST_ANCESTORS)
        self.assertEqual(0, len(violations))

    def test_violations(self):
        """Test violations are found"""
        violations = self.rule_book.find_violations(
            'user@example.com', self.TEST_BAD_ANCESTORS)

        self.assertEqual(0, len(violations))

class ExternalProjectAccessRuleTest(ForsetiTestCase):
    """Tests for the ExternalProjectAccessRuleBook."""

    TEST_ANCESTORS = [Project('123'),
                      Folder('456'),
                      Organization('7890')]

    def test_single_item_in_rule_match(self):
        """Test no violations are found with single item in rule"""
        rule = engine_module.Rule(rule_name='test_single_item_in_rule_match',
                                  rule_index=0,
                                  rules=[Organization('7890')])
        violation = rule.find_violation('user1@example.com',
                                        self.TEST_ANCESTORS)
        self.assertIsNone(violation)

    def test_multi_items_in_rule_match(self):
        """Test no violations are found with multiple items in rule"""
        rule = engine_module.Rule(rule_name='test_multi_items_in_rule_match',
                                  rule_index=0,
                                  rules=[Folder('456'), Organization('7890')])
        violation = rule.find_violation('user1@example.com',
                                        self.TEST_ANCESTORS)
        self.assertIsNone(violation)

    def test_single_item_no_match(self):
        """Test violations are found with single item in rule"""
        rule = engine_module.Rule(rule_name='test_single_item_no_match',
                                  rule_index=0,
                                  rules=[Organization('789')])
        violation = rule.find_violation('user1@example.com',
                                        self.TEST_ANCESTORS)

        self.assertEqual(0, violation.rule_index)
        self.assertEqual('test_single_item_no_match',
                         violation.rule_name)
        self.assertEqual('projects/123', violation.full_name)
        self.assertEqual('projects/123,folders/456,organizations/7890',
                         violation.resource_data)


    def test_multi_items_no_match(self):
        """Test violations are found with multiple items in rule"""
        rule = engine_module.Rule(rule_name='test_multi_items_no_match',
                                  rule_index=0,
                                  rules=[Folder('45'), Organization('789')])
        violation = rule.find_violation('user1@example.com',
                                        self.TEST_ANCESTORS)

        self.assertEqual(0, violation.rule_index)
        self.assertEqual('test_multi_items_no_match',
                         violation.rule_name)
        self.assertEqual('projects/123', violation.full_name)
        self.assertEqual('projects/123,folders/456,organizations/7890',
                         violation.resource_data)

if __name__ == '__main__':
    unittest.main()
