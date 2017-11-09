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

"""Tests the ForwardingRuleRulesEngine."""

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import forwarding_rule_rules_engine as fre
from tests.unittest_utils import get_datafile_path


class FowardingRulesEngineTest(ForsetiTestCase):
    """Tests for the ForwardingRuleRulesEngine."""

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__,
        	'fwd_test_rules_1.yaml')
        rules_engine = fre.ForwardingRuleRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_protocol_fails(self):
        """Test that a rule without a protocol cannot be created."""
        rules_local_path = get_datafile_path(__file__,
        	'fwd_test_rules_2.yaml')
        rules_engine = fre.ForwardingRuleRulesEngine(rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()
