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

import mock
import unittest

import google.cloud.security.actions.action_config_validator as acv
from tests.unittest_utils import ForsetiTestCase
from tests.actions import action_config_data


class ActionsConfigValidatorTest(ForsetiTestCase):
  """."""
  def setUp(self):
    self.valid_config = action_config_data.VALID_CONFIG1
    self.invalid_config = action_config_data.INVALID_CONFIG1

  def test_load_actions(self):
    _, errors = acv.ActionsConfigValidator._load_actions(self.valid_config)
    self.assertEqual([], errors)

  def test_load_actions_errors(self):
    _, errors = acv.ActionsConfigValidator._load_actions(self.invalid_config)
    expected_errors = [
        acv.MissingRequiredActionField('id'),
        acv.DuplicateActionIdError('action.1')
    ]
    self.assert_errors_equal(expected_errors, errors)

  def test_check_action_type(self):
    for action in self.valid_config.get('actions', []):
      result = acv.ActionsConfigValidator._check_action_type(action)
      self.assertIsNone(result)

  def test_check_action_type_errors(self):
    errors = []
    for action in self.invalid_config.get('actions', []):
      result = acv.ActionsConfigValidator._check_action_type(action)
      if result is not None:
        errors.append(result)
    expected = [acv.ActionTypeDoesntExist(
        'google.cloud.security.actions.ActionDoesntExist')]
    self.assert_errors_equal(expected, errors)

  # TODO: once the code for the rules has been submitted, this can be enabled.
  # def test_check_trigger(self):
  #   for action in self.valid_config.get('actions', []):
  #     result = acv.ActionsConfigValidator._check_trigger(action)
  #     self.assertIsNone(result)

  def test_check_trigger_errors(self):
    errors = []
    for action in self.invalid_config.get('actions', []):
      result = acv.ActionsConfigValidator._check_trigger(action)
      if result is not None:
        errors.append(result)
    expected = [
        acv.TriggerDoesntExist('rules.rule_doesnt_exist.*'),
        acv.TriggerDoesntExist('rules.rule_doesnt_exist.*'),
        acv.TriggerDoesntExist('rules.rule_doesnt_exist.*')
    ]
    self.assert_errors_equal(expected, errors)

  def assert_errors_equal(self, expected, errors):
    self.assertEqual(len(expected), len(errors))
    for exp, err in zip(expected, errors):
      self.assertTrue(type(exp) is type(err) and exp.args == err.args)


if __name__ == '__main__':
  unittest.main()
