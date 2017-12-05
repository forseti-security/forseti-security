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

""" Unit Tests for Scanner DAO. """

import ast
import unittest

from google.cloud.forseti.scanner import dao as scanner_dao
from tests.services.utils.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase


FAKE_VIOLATIONS = [
    {'resource_id': 'fake_firewall_111',
     'rule_name': 'disallow_all_ports_111',
     'rule_index': 111,
     'violation_data':
         {'policy_names': ['fw-tag-match_111'],
          'recommended_actions':
              {'DELETE_FIREWALL_RULES': ['fw-tag-match_111']}},
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION_111',
     'resource_type': 'firewall_rule'},

    {'resource_id': 'fake_firewall_222',
     'rule_name': 'disallow_all_ports_222',
     'rule_index': 222,
     'violation_data':
         {'policy_names': ['fw-tag-match_222'],
          'recommended_actions':
              {'DELETE_FIREWALL_RULES': ['fw-tag-match_222']}},
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION_222',
     'resource_type': 'firewall_rule'},
]


class ScannerDaoTest(ForsetiTestCase):
    """Test scanner data access."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def test_save_violations(self):
        """Test violations can be saved."""

        engine = create_test_engine()
        violation_access_cls = scanner_dao.define_violation(
            'fake_model_88888', engine)
        violation_access = violation_access_cls(engine)

        violation_access.create(FAKE_VIOLATIONS)
        saved_violations = violation_access.list()

        self.assertEquals(len(FAKE_VIOLATIONS), len(saved_violations))

        fake_violations111 = FAKE_VIOLATIONS[0]
        saved_violation111 = saved_violations[0]
        self.assertEquals(fake_violations111.get('resource_type'),
                          saved_violation111.resource_type)
        self.assertEquals(fake_violations111.get('rule_name'),
                          saved_violation111.rule_name)
        self.assertEquals(fake_violations111.get('rule_index'),
                          saved_violation111.rule_index)
        self.assertEquals(fake_violations111.get('violation_type'),
                          saved_violation111.violation_type)
        self.assertDictEqual(fake_violations111.get('violation_data'),
                             ast.literal_eval(saved_violation111.data))

        fake_violations222 = FAKE_VIOLATIONS[1]
        saved_violation222 = saved_violations[1]
        self.assertEquals(fake_violations222.get('resource_type'),
                          saved_violation222.resource_type)
        self.assertEquals(fake_violations222.get('rule_name'),
                          saved_violation222.rule_name)
        self.assertEquals(fake_violations222.get('rule_index'),
                          saved_violation222.rule_index)
        self.assertEquals(fake_violations222.get('violation_type'),
                          saved_violation222.violation_type)
        self.assertDictEqual(fake_violations222.get('violation_data'),
                             ast.literal_eval(saved_violation222.data))


if __name__ == '__main__':
    unittest.main()
