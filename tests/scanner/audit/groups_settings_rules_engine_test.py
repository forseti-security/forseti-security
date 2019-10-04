# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Tests the GroupsSettingsRulesEngine module."""

from google.cloud.forseti.common.gcp_type import groups_settings
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit import groups_settings_rules_engine
from tests.scanner.audit.data.groups_settings_test_data import (
    SETTINGS_1, SETTINGS_2, SETTINGS_3, SETTINGS_4, SETTINGS_5)
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path

BLACKLIST_RULE_NAME = 'Cant allow external members with INVITED_CAN_JOIN'
WHITELIST_RULE_NAME = 'All groups with iam policies should have all of ' \
                      + 'these settings'


class RuleTest(ForsetiTestCase):
    """Tests for the GroupsSettingsRulesEngine Rule class."""

    def setUp(self):
        self.rules_local_path = get_datafile_path(
            __file__,
            'groups_settings_test_rules.yaml')
        self.rules = dict()
        parsed_rules = file_loader.read_and_parse_file(self.rules_local_path)
        for index, rule in enumerate(parsed_rules['rules']):
            self.rules[rule['name']] = groups_settings_rules_engine.Rule(
                rule_name=rule['name'],
                rule_index=index,
                rule=rule
            )

    def test_find_blacklist_violation_all_violate(self):
        """Test that a blacklist Rule returns violations when all settings
        are in violation."""
        rule = self.rules[BLACKLIST_RULE_NAME]
        group_settings_type = groups_settings.GroupsSettings.from_json(
            'settings1@testing.com',
            SETTINGS_1['settings'])
        actual_result = rule.find_blacklist_violation(group_settings_type)
        expected_result = ['allowExternalMembers', 'whoCanJoin']
        self.assertListEqual(expected_result, actual_result)

    def test_find_blacklist_violation_none_violate(self):
        """Test that a blacklist Rule returns no violations when no settings
        are in violation."""
        rule = self.rules[BLACKLIST_RULE_NAME]
        group_settings_type = groups_settings.GroupsSettings.from_json(
            'settings2@testing.com',
            SETTINGS_2['settings'])
        actual_result = rule.find_blacklist_violation(group_settings_type)
        expected_result = []
        self.assertListEqual(expected_result, actual_result)

    def test_find_blacklist_violation_some_violate(self):
        """Test that a blacklist Rule returns no violations when some settings
        are in violation."""
        rule = self.rules[BLACKLIST_RULE_NAME]
        group_settings_type = groups_settings.GroupsSettings.from_json(
            'settings3@testing.com',
            SETTINGS_3['settings'])
        actual_result = rule.find_blacklist_violation(group_settings_type)
        expected_result = []
        self.assertListEqual(expected_result, actual_result)

    def test_find_whitelist_violation_none_violate(self):
        """Test that a whitelist Rule returns no violations when no settings
        are in violation."""
        rule = self.rules[WHITELIST_RULE_NAME]
        group_settings_type = groups_settings.GroupsSettings.from_json(
            'settings4@testing.com',
            SETTINGS_4['settings'])
        actual_result = rule.find_whitelist_violation(group_settings_type)
        expected_result = []
        self.assertListEqual(expected_result, actual_result)

    def test_find_whitelist_violation_some_violate(self):
        """Test that a whitelist Rule returns some violations when some
        settings are in violation."""
        rule = self.rules[WHITELIST_RULE_NAME]
        group_settings_type = groups_settings.GroupsSettings.from_json(
            'settings5@testing.com',
            SETTINGS_5['settings'])
        actual_result = rule.find_whitelist_violation(group_settings_type)
        expected_result = ['allowExternalMembers', 'whoCanJoin']
        self.assertListEqual(expected_result, actual_result)
