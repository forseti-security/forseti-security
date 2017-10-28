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

"""Rules Config Validator tests.

This is for the actual RuleConfigValidator class and does not include tests
for the json schema validator.
"""

import mock
import os
import unittest
import MySQLdb

from google.cloud.security.auditor import rules_config_validator as rcv
from tests.auditor.test_data import test_auditor_data
from tests.unittest_utils import ForsetiTestCase


class RulesConfigValidator(ForsetiTestCase):

    def setUp(self):
        self.validator = rcv.RulesConfigValidator
        self.valid_rules1 = test_auditor_data.VALID_RULES1
        self.invalid_rules1 = test_auditor_data.INVALID_RULES1

    def test_check_unmatched_config_vars(self):
        """Test _check_unmatched_config_vars()."""
        rule = self.valid_rules1.get('rules')[0]
        rule_config = rule.get('configuration')
        config_vars = set(rule_config.get('variables', []))
        config_resources = rule_config.get('resources', {})

        actual_unmatched = self.validator._check_unmatched_config_vars(
            rule['id'], config_vars, config_resources)

        self.assertFalse(actual_unmatched)

    def test_check_invalid_conditions(self):
        """Test _check_invalid_conditions()."""
        rule = self.valid_rules1.get('rules')[0]
        rule_config = rule.get('configuration')
        config_vars = set(rule_config.get('variables', []))
        condition = rule_config.get('condition', {})

        invalid_conditions = self.validator._check_invalid_conditions(
            rule['id'], config_vars, condition)

        self.assertFalse(invalid_conditions)

    def test_validate(self):
        """Test validate() works for well formed generic configurations."""
        pass

    @mock.patch('google.cloud.security.auditor.rules_config_validator.DuplicateRuleIdError', autospec=True)
    def test_duplicate_rule_ids_error(self, mock_dup_id_error):
        """Test that validate() fails when finding duplicate ids."""
        self.validator._validate_schema = mock.MagicMock(
            return_value=[self.invalid_rules1, []])
        self.validator._check_unmatched_config_vars = mock.MagicMock(
            return_value=[])
        self.validator._check_invalid_conditions = mock.MagicMock(
            return_value=[])

        with self.assertRaises(rcv.InvalidRulesConfigError):
            self.validator.validate('fake/path')

        calls = [
            mock.call(dup_id)
            for dup_id in test_auditor_data.INVALID_RULES1_DUP_IDS]

        mock_dup_id_error.assert_has_calls(calls, any_order=True)


if __name__ == '__main__':
    unittest.main()
