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

"""Rules Engine and Rules tests."""

import mock
import unittest
import MySQLdb

from google.cloud.security.auditor.rules import rule
from tests.unittest_utils import ForsetiTestCase


class RulesEngineTest(ForsetiTestCase):

    def setUp(self):
        pass


class RulesTest(ForsetiTestCase):
    
    def setUp(self):
        pass

    def test_create_rule(self):
        """Test create_rule()."""
        rule_type = 'google.cloud.security.auditor.rules.rule.Rule'
        fake_rule_def = {
            'type': rule_type,
            'id': 'rules.fake.1',
            'description': 'Fake rule',
            'configuration': {
                'variables': [
                    'xyz'
                ],
                'resources': [
                    {
                        'type': 'google.cloud.security.common.gcp_type.project.Project',
                        'variables': [
                            {'xyz': 'project_id'}
                        ]
                    }
                ],
                'condition': [
                    '1 == 1'
                ]
            }
        }

        new_rule = rule.Rule.create_rule(fake_rule_def)
        self.assertEquals(rule_type, new_rule.type)


if __name__ == '__main__':
    unittest.main()
