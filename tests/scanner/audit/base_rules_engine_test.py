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

"""Test BaseRulesEngine and associated modules."""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import rules as audit_rules
from google.cloud.forseti.scanner.audit import errors as audit_errors


class BaseRulesEngineTest(ForsetiTestCase):
    """Test BaseRulesEngine."""

    def test_init_with_rules_no_error(self):
        """Test the __init__() with a rules path."""
        path1 = 'path/to/rules'
        base = bre.BaseRulesEngine(rules_file_path=path1)
        self.assertEquals(path1, base.full_rules_path)

        path2 = '  path/to/rules   '
        base2 = bre.BaseRulesEngine(rules_file_path=path2)
        self.assertEqual(path2.strip(), base2.full_rules_path)

    def test_init_with_no_rules_raises_error(self):
        """Test __init__() with no rules raises InvalidRuleDefinitionError."""
        with self.assertRaises(audit_errors.InvalidRuleDefinitionError):
            bre.BaseRulesEngine()

    def test_build_rule_book_not_implemented_error(self):
        """Test that invoking build_rule_book() raises NotImplementedError."""
        base = bre.BaseRulesEngine('foo')
        with self.assertRaises(NotImplementedError):
            base.build_rule_book({})


class BaseRulesBookTest(ForsetiTestCase):
    """Test BaseRulesBook."""

    def test_cannot_instantiate(self):
        """Test that add_rule() raises NotImplementedError."""
        with self.assertRaises(TypeError):
            bre.BaseRuleBook()


class RuleAppliesToTest(ForsetiTestCase):
    """Test RuleAppliesTo."""

    def test_rule_applies_is_verified(self):
        """Test valid RuleAppliesTo."""

        self.assertEqual(
            audit_rules.RuleAppliesTo.SELF,
            audit_rules.RuleAppliesTo.verify(audit_rules.RuleAppliesTo.SELF))

        self.assertEqual(
            audit_rules.RuleAppliesTo.CHILDREN,
            audit_rules.RuleAppliesTo.verify(audit_rules.RuleAppliesTo.CHILDREN))

        self.assertEqual(
            audit_rules.RuleAppliesTo.SELF_AND_CHILDREN,
            audit_rules.RuleAppliesTo.verify(
              audit_rules.RuleAppliesTo.SELF_AND_CHILDREN))

    def test_invalid_rule_applies_raises_error(self):
        """Test invalid RuleAppliesTo raises error."""
        with self.assertRaises(audit_errors.InvalidRulesSchemaError):
            audit_rules.RuleAppliesTo.verify('invalid')


if __name__ == '__main__':
    unittest.main()
