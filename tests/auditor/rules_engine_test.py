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

"""Rules Engine tests."""

import json
import mock
import unittest

from google.cloud.forseti.auditor import condition_parser
from google.cloud.forseti.auditor import rules_engine
from google.cloud.forseti.auditor import rules_config_validator
from google.cloud.forseti.auditor.rules import rule
from google.cloud.forseti.services.actions import action_engine_pb2
from google.cloud.forseti.services.auditor import storage
from tests.auditor.test_data import test_auditor_data
from tests.unittest_utils import ForsetiTestCase


class RulesEngineTest(ForsetiTestCase):
    """RulesEngineTest."""

    def setUp(self):
        """Setup."""
        pass

    @mock.patch.object(
        rules_config_validator.RulesConfigValidator, 'validate')
    def test_setup(self, mock_rules_validate):
        """Test setup()."""
        fake_rules_path = '/fake/path/rules.yaml'
        rules_eng = rules_engine.RulesEngine(fake_rules_path)
        mock_rules_validate.return_value = test_auditor_data.FAKE_RULES_CONFIG1
        expected_rules = [
            rule.Rule.create_rule(r)
            for r in test_auditor_data.FAKE_RULES_CONFIG1.get('rules', [])]

        rules_eng.setup()

        self.assertEquals(expected_rules, rules_eng.rules)
        self.assertEquals(fake_rules_path, rules_eng.rules_config_path)

    @mock.patch.object(rule.Rule, 'audit', autospec=True)
    def test_evaluate_rules(self, mock_rule_audit):
        """Test evaluate_rules() returns expected results."""
        fake_rules_path = '/fake/path/rules.yaml'
        rules_eng = rules_engine.RulesEngine(fake_rules_path)
        rules_eng.rules = [
            rule.Rule.create_rule(r)
            for r in test_auditor_data.FAKE_RULES_CONFIG1['rules']]

        proj_data = {"name": "project-test",
                     "parent": {"type": "organization", "id": "123456789012"},
                     "projectId": "project-test",
                     "projectNumber": "111111111111",
                     "lifecycleState": "ACTIVE",
                     "createTime": "2018-01-01T00:00:00.000Z"}

        fake_project = mock.MagicMock(
            data=json.dumps(proj_data),
            type='project',
            type_name='project/%s' % proj_data['projectId'])
        fake_result = action_engine_pb2.RuleResult(
            rule_id=rules_eng.rules[0].rule_name,
            resource_type_name=fake_project.type_name,
            status=storage.RuleResultStatus.ACTIVE.value)
        expected_results = [(rules_eng.rules[0], fake_result),
                            (rules_eng.rules[1], None),
                            ]
        mock_rule_audit.side_effect = [
            fake_result,
            None
        ]
        actual_results = list(rules_eng.evaluate_rules(fake_project))
        self.assertEquals(expected_results, actual_results)


if __name__ == '__main__':
    unittest.main()
