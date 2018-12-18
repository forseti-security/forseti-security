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

"""Tests the ResourceRulesEngine."""

import copy
import itertools
import json
import mock
import tempfile
import unittest
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import lien
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import resource_rules_engine
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path
from tests.scanner.test_data import fake_resource_scanner_data as data


def get_rules_engine_with_rule(rule):
    with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
        f.write(rule)
        f.flush()
        rules_engine = resource_rules_engine.ResourceRulesEngine(
            rules_file_path=f.name)
        rules_engine.build_rule_book()
    return rules_engine


class ResourceRulesEngineTest(ForsetiTestCase):
    """Tests for the ResourceRulesEngine."""

    def setUp(self):
        resource_rules_engine.LOGGER = mock.MagicMock()

    # def test_build_rule_book_from_local_yaml_file(self):
    #     rules_engine = get_rules_engine_with_rule(
    #         Rules.organization_rule, data.ORGANIZATION.id)
    #     self.assertEqual(1, len(rules_engine.rule_book.resource_to_rules))

    # def test_build_rule_book_no_resource(self):
    #     with self.assertRaises(InvalidRulesSchemaError):
    #         get_rules_engine_with_rule(Rules.base_rule, '')

    def test_get_applicable_resource_types(self):
        rule = """
rules:
- name: rule 1
  mode: required
  resource_types: [project]
  resource_trees: []
- name: rule 2
  mode: required
  resource_types: [organization, project]
  resource_trees: []
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_types = rules_engine.rule_book.get_applicable_resource_types()
        self.assertEqual(got_types, set(['organization', 'project']))

    def test_find_violations_single_node_match(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [project]
  resource_trees:
  - type: project
    resource_id: p1
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations([data.PROJECT1]))
        self.assertEqual(got_violations, [])

    def test_find_violations_single_node_no_match(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [project]
  resource_trees:
  - type: project
    resource_id: p1
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(
            [data.PROJECT1, data.PROJECT2]))
        self.assertEqual(got_violations, data.build_violations(data.PROJECT2))

    def test_find_violations_multiple_roots(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [project]
  resource_trees:
  - type: project
    resource_id: p1
  - type: project
    resource_id: p2
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(
            [data.PROJECT1, data.PROJECT2]))
        self.assertEqual(got_violations, [])

    def test_find_violations_child(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [organization, project]
  resource_trees:
  - type: organization
    resource_id: '234'
    children:
    - type: project
      resource_id: p1
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(
            [data.ORGANIZATION, data.PROJECT1]))
        self.assertEqual(got_violations, [])

    def test_find_violations_missing(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [project]
  resource_trees:
  - type: project
    resource_id: p1
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations([]))
        violation = data.build_violations(data.PROJECT2)[0]
        violation = resource_rules_engine.RuleViolation(
            resource_id='p1',
            resource_name='p1',
            resource_type='project',
            full_name='p1',
            rule_index=0,
            rule_name='Resource test rule',
            violation_type='RESOURCE_VIOLATION',
            resource_data='',
        )
        self.assertEqual(got_violations, [violation])

    def test_find_violations_wildcard(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [project]
  resource_trees:
  - type: project
    resource_id: '*'
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations([data.PROJECT1]))
        self.assertEqual(got_violations, [])

    def test_find_violations_wildcard_and_sibling(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [organization, project]
  resource_trees:
  - type: organization
    resource_id: '*'
  - type: organization
    resource_id: '234'
    children:
      - type: project
        resource_id: p1
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(
            [data.ORGANIZATION, data.PROJECT1]))
        self.assertEqual(got_violations, [])

    def test_find_violations_empty_tree(self):
        rule = """
rules:
- name: Resource test rule
  mode: required
  resource_types: [organization]
  resource_trees: []
"""
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations([data.ORGANIZATION]))
        self.assertEqual(got_violations,
                         data.build_violations(data.ORGANIZATION))

if __name__ == '__main__':
    unittest.main()
