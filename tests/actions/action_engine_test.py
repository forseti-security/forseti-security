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
import os
import unittest

from google.cloud.forseti.services.actions import action_engine as ae
from tests.unittest_utils import ForsetiTestCase
from tests.actions import action_config_data


class ActionTest(ForsetiTestCase):

  def setUp(self):
    self.action = ae.Action({}, 'id', 'type')

  def test_act(self):
    with self.assertRaises(NotImplementedError):
      self.action.act('result')


class SampleActionTest(ForsetiTestCase):

  def test_from_dict(self):
    action = ae.SampleAction.from_dict({'id': 'id', 'type': 'type'})
    self.assertEqual('id', action.action_id)
    self.assertEqual('type', action.type)

  def test_from_dict_errors(self):
    with self.assertRaises(ae.MissingRequiredActionField):
      action = ae.SampleAction.from_dict({'type': 'type'})

  def test_from_dict_errors_2(self):
    with self.assertRaises(ae.MissingRequiredActionField):
      action = ae.SampleAction.from_dict({'id': 'id'})

  def test_act(self):
    success_action = ae.SampleAction({}, 'id', 'type', 0, 'info1')
    error_action = ae.SampleAction({}, 'id', 'type', 1, 'info2')
    success_act_result = list(success_action.act(['result']))
    self.assertSameStructure(
        ae.RuleResult(
            rule_result='result',
            code=0,
            action_id='id',
            info='info1'
        ),
        success_act_result[0]
    )
    error_act_result = list(error_action.act(['result']))
    self.assertSameStructure(
        ae.RuleResult(
            rule_result='result',
            code=1,
            action_id='id',
            info='info2'
        ),
        error_act_result[0]
    )


class ActionEngineTest(ForsetiTestCase):

  def setUp(self):
    self.action_engine = ae.ActionEngine(action_config_data.VALID_CONFIG1_PATH)

  def test_get_action_class(self):
    action_class = ae.get_action_class(
        'google.cloud.forseti.services.actions.action_engine.SampleAction')
    self.assertEqual(ae.SampleAction, action_class)

  def test_get_action_class_errors(self):
    with self.assertRaises(ae.ActionImportError):
      action_class = ae.get_action_class('doesnt.exist')

  def test_create_actions(self):
    expected = [
        ae.SampleAction.from_dict(
            {
                'id': 'action.1', 
                'type': ('google.cloud.forseti.services.actions.action_engine.'
                         'SampleAction'),
                'group_by': 'resource.project',
                'triggers': ['*'],
            }
        ),
        ae.SampleAction.from_dict(
            {
                'id': 'action.2', 
                'type': ('google.cloud.forseti.services.actions.action_engine.'
                         'Action'),
                'group_by': 'resource.project',
                'triggers': ['*'],
            }
        )
    ]
    self.action_engine._action_configs.append({
        'id': 'action.2', 
        'type': ('google.cloud.forseti.services.actions.action_engine.'
                 'Action'),
        'group_by': 'resource.project',
        'triggers': ['*'],
    })
    self.action_engine.action_types[('google.cloud.forseti.services.actions.'
                                     'action_engine.Action')] = ae.SampleAction
    self.action_engine._create_actions()
    self.assertEqual(expected, self.action_engine.actions)

  def test_process_results(self):
    results = self.action_engine.process_results(['result'])
    expected = {
        'result': [
            ae.RuleResult(
                rule_result='result',
                code=0,
                action_id='action.1',
                info=''
            ),
        ],
    }
    self.assertSameStructure(expected, results)


if __name__ == '__main__':
  unittest.main()
