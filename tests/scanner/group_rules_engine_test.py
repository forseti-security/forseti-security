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

"""Tests the GroupRulesEngine."""

import yaml

from google.apputils import basetest
from google.cloud.security.scanner.audit import group_rules_engine
from tests.unittest_utils import get_datafile_path


class GroupRulesEngineTest(basetest.TestCase):
    """Tests for the GroupRulesEngine."""

    def setUp(self):
        """Set up."""
        pass

    def test_create_group_rules_engine(self):
        """Test that the Group Rules Engine is created correctly."""
        rules_local_path = get_datafile_path(__file__, 'group_test_rules_1.yaml')
        rules_engine = group_rules_engine.GroupRulesEngine(
            rules_file_path=rules_local_path)

        with open(rules_local_path, 'r') as f:
            rules_file = yaml.load(f)
        expected_rules = rules_file.get('rules')
        expected_resources = expected_rules[0].get('resource')
        # Verify the Groups Rule Book is built correctly.
        
        # Verify the rule_defs.    
        self.assertEquals(rules_file,
                          rules_engine.rule_book.rule_defs)

        # Verify the resource rules map.
        self.assertEquals(1, len(rules_engine.rule_book.resource_rules_map))

        # Verify the resources.
        expected_resource = expected_resources[0]
        resource_rules_map_key, resource_rules = (
            rules_engine.rule_book.resource_rules_map.items()[0])
        resource = resource_rules_map_key[0]

        self.assertEquals(expected_resource.get('resource_ids')[0],
                          resource.id)
        self.assertEquals(expected_resource.get('type'),
                          resource.type)
        self.assertEquals(expected_resource.get('applies_to'),
                          resource_rules_map_key[1])

        # Verify the rules.
        rules = list(resource_rules.rules)
        self.assertEquals(len(expected_rules), len(rules))

        rule = rules[0]
        expected_members = rules_file.get('rules')[0].get('members')
        self.assertEquals(len(expected_members), len(rule.members))

        expected_member = expected_members[0]
        self.assertEquals(expected_member.get('email') , rule.members[0].email)
        self.assertEquals(expected_member.get('role'), rule.members[0].role)
        self.assertEquals(expected_member.get('type'), rule.members[0].type)


if __name__ == '__main__':
    basetest.main()
