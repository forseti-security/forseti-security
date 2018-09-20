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
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import lien_rules_engine
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path
from tests.scanner.test_data import fake_lien_scanner_data

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

class Data(object):
    lien_json = """{
    "name": "liens/l1",
    "parent": "projects/p1",
    "restrictions": ["resourcemanager.projects.delete"],
    "origin": "testing",
    "createTime": "2018-09-05T14:45:46.534Z"
}
"""
    organization_with_lien = organization.Organization(
        '234',
        display_name='Organization 234',
        full_name='organization/234/',
        data='fake_org_data_234',
    )

    project_with_lien = project.Project(
        'p1',
        project_number=11223344,
        display_name='Project with lien',
        parent=organization,
        full_name='organization/234/project/p1/',
        data='fake_project_data_2341',
    )

    project_without_lien = project.Project(
        'p2',
        project_number=11223345,
        display_name='Project without lien',
        parent=organization,
        full_name='organization/234/project/p2/',
        data='fake_project_data_2342',
    )

    liens = [lien.Lien.from_json(project_with_lien, 'lien/l1', lien_json)]

    violations = [lien_rules_engine.RuleViolation(
        resource_id='lien/l1',
        resource_type=resource.ResourceType.LIEN,
        full_name='organization/234/project/p1/lien/l1/',
        rule_index=0,
        rule_name='Lien test rule',
        violation_type='LIEN_VIOLATION',
        resource_data=lien_json,
    )]

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
        rule = Rules.organization_rule.format(id='234')
        rules_engine = get_rules_engine_with_rule(rule)
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_resource(self):
        rule = Rules.base_rule
        with self.assertRaises(InvalidRulesSchemaError):
            get_rules_engine_with_rule(rule)

    def test_find_violations_project_rule_no_violations(self):
        rule = Rules.projects_rule.format(ids=['p1'])
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(Data.liens))
        self.assertEqual(got_violations, [])

    def test_find_violations_project_rule_missing_restrictions(self):
        rule = Rules.projects_rule.format(ids=['p1'])
        rule = rule.replace('resourcemanager.projects.delete', 'foo')
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(Data.liens))
        self.assertEqual(got_violations, Data.violations)

    # def test_find_violations_missing_lien(self):
    #     rule = Rules.projects_rule.format(ids=['p2'])
    #     rules_engine = get_rules_engine_with_rule(rule)
    #     got_violations = list(rules_engine.find_violations(Data.liens))
    #     self.assertEqual(got_violations, Data.violations)

    def test_find_violations_organization_rule(self):
        rule = Rules.organization_rule.format(id='234')
        rule = rule.replace('resourcemanager.projects.delete', 'foo')
        rules_engine = get_rules_engine_with_rule(rule)
        got_violations = list(rules_engine.find_violations(Data.liens))
        self.assertEqual(got_violations, Data.violations)

if __name__ == '__main__':
    unittest.main()
