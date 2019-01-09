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
    restrictions: {restrictions}
"""

    organization_rule = base_rule + """
    resource:
      - type: organization
        resource_ids:
          - "{id}"
"""

    projects_rule = base_rule + """
    resource:
      - type: project
        resource_ids:
          - "{id}"
"""

def get_rules_engine_with_rule(rule_tmpl, rid, restrictions=None):
    if not restrictions:
        restrictions = ['resourcemanager.projects.delete']

    rule = rule_tmpl.format(id=rid, restrictions=restrictions)

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
        rules_engine = get_rules_engine_with_rule(
            Rules.organization_rule, data.ORGANIZATION.id)
        self.assertEqual(1, len(rules_engine.rule_book.resource_to_rules))

    def test_build_rule_book_no_resource(self):
        with self.assertRaises(InvalidRulesSchemaError):
            get_rules_engine_with_rule(Rules.base_rule, '')

    def test_find_violations_project_rule_no_violations(self):
        rules_engine = get_rules_engine_with_rule(
            Rules.projects_rule, data.PROJECT.id)
        got_violations = list(rules_engine.find_violations(
            data.PROJECT, [data.LIEN]))
        self.assertEqual(got_violations, [])

    def test_find_violations_project_rule_missing_restrictions(self):
        rules_engine = get_rules_engine_with_rule(
            Rules.projects_rule, data.PROJECT.id, restrictions=['foo'])
        got_violations = list(rules_engine.find_violations(
            data.PROJECT, [data.LIEN]))
        self.assertEqual(got_violations, data.VIOLATIONS)

    def test_find_violations_organization_rule(self):
        rules_engine = get_rules_engine_with_rule(
            Rules.organization_rule, data.ORGANIZATION.id, restrictions=['foo'])
        got_violations = list(rules_engine.find_violations(
            data.PROJECT, [data.LIEN]))
        self.assertEqual(got_violations, data.VIOLATIONS)

    def test_find_violations_project_missing_lien(self):
        rules_engine = get_rules_engine_with_rule(
            Rules.projects_rule, data.PROJECT.id)
        got_violations = list(rules_engine.find_violations(data.PROJECT, []))
        self.assertEqual(got_violations, data.VIOLATIONS)

    def test_find_violations_project_wildcard(self):
        rules_engine = get_rules_engine_with_rule(
            Rules.projects_rule, '*')
        got_violations = list(rules_engine.find_violations(data.PROJECT, []))
        self.assertEqual(got_violations, data.VIOLATIONS)

    def test_find_violations_projects_multiple_liens(self):
        id_to_restrictions = {'l1': ['a', 'b'], 'l2': ['c']}

        liens = []

        for lid, restrictions in id_to_restrictions.iteritems():
            lien_dict = {
                'name': 'liens/' + lid,
                'parent': 'projects/p1',
                'restrictions': restrictions,
                'origin': 'testing-' + lid,
                'createTime': '2018-09-05T14:45:46.534Z',
            }

            liens.append(lien.Lien.from_json(
                data.PROJECT, json.dumps(lien_dict)))

        rules_engine = get_rules_engine_with_rule(
            Rules.projects_rule, data.PROJECT.id, restrictions=['a', 'c'])
        got_violations = list(rules_engine.find_violations(data.PROJECT, liens))
        self.assertEqual(got_violations, [])


if __name__ == '__main__':
    unittest.main()
