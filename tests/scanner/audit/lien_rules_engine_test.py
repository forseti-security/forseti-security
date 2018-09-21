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

"""Tests the LienRulesEngine."""

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
from google.cloud.forseti.scanner.audit import lien_rules_engine
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path
from tests.scanner.test_data import fake_lien_scanner_data as data

class Rules(object):
    base_rule = """
rules:
  - name: Lien test rule
    mode: required
    restrictions: [resourcemanager.projects.delete]
"""

    organization_rule = base_rule + """
    resource:
      - type: organization
        resource_ids:
        - {id}
"""

    projects_rule = base_rule + """
    resource:
      - type: project
        resource_ids: {ids}
"""


def get_rules_engine_with_rule(rule):
    with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
        f.write(rule)
        f.flush()
        rules_engine = lien_rules_engine.LienRulesEngine(
            rules_file_path=f.name)
        rules_engine.build_rule_book()
    return rules_engine


class LienRulesEngineTest(ForsetiTestCase):
    """Tests for the LienRulesEngine."""

    def setUp(self):
        lien_rules_engine.LOGGER = mock.MagicMock()

    def test_build_rule_book_from_local_yaml_file(self):
        rule = Rules.organization_rule.format(id=data.ORGANIZATION_WITH_LIEN.id)
        rules_engine = get_rules_engine_with_rule(rule)
        self.assertEqual(1, len(rules_engine.rule_book.resource_to_rules))

    def test_build_rule_book_no_resource(self):
        rule = Rules.base_rule
        with self.assertRaises(InvalidRulesSchemaError):
            get_rules_engine_with_rule(rule)

    def test_find_violations_project_rule_no_violations(self):
        rule = Rules.projects_rule.format(ids=[data.PROJECT_WITH_LIEN.id])
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(data.LIENS))
        self.assertEqual(got_violations, [])

    def test_find_violations_project_rule_missing_restrictions(self):
        rule = Rules.projects_rule.format(ids=[data.PROJECT_WITH_LIEN.id])
        rule = rule.replace('resourcemanager.projects.delete', 'foo')
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(data.LIENS))
        self.assertEqual(got_violations, data.VIOLATIONS)

    def test_find_violations_organization_rule(self):
        rule = Rules.organization_rule.format(id=data.ORGANIZATION_WITH_LIEN.id)
        rule = rule.replace('resourcemanager.projects.delete', 'foo')
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(data.LIENS))
        self.assertEqual(got_violations, data.VIOLATIONS)

    def test_find_violations_missing_lien(self):
        project = data.PROJECT_WITHOUT_LIEN
        rule = Rules.projects_rule.format(ids=[project.id])
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(data.LIENS))
        want_violations = [lien_rules_engine.RuleViolation(
            resource_id=project.id,
            resource_type=project.type,
            full_name='project/p2',
            rule_index=0,
            rule_name='Lien test rule',
            violation_type='LIEN_VIOLATION',
            resource_data='',
        )]
        self.assertEqual(got_violations, want_violations)

if __name__ == '__main__':
    unittest.main()
