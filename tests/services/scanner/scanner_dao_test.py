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

from itertools import izip
import json
import mock
import unittest

from google.cloud.forseti.services.scanner import dao as scanner_dao
from tests.unittest_utils import ForsetiTestCase
from tests.services.util.db import create_test_engine


FAKE_INVENTORY_INDEX_ID = 'aaa'
FAKE_VIOLATION_HASH = (u'111111111111111111111111111111111111111111111111111111'
                        '111111111111111111111111111111111111111111111111111111'
                        '11111111111111111111')

FAKE_EXPECTED_VIOLATIONS = [
    {'inventory_index_id': FAKE_INVENTORY_INDEX_ID,
     'resource_id': 'fake_firewall_111',
     'full_name': 'full_name_111',
     'rule_name': 'disallow_all_ports_111',
     'rule_index': 111,
     'violation_data':
         {'policy_names': ['fw-tag-match_111'],
          'recommended_actions':
              {'DELETE_FIREWALL_RULES': ['fw-tag-match_111']}},
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION_111',
     'resource_type': 'firewall_rule',
     'inventory_data': 'inventory_data_111',
     'violation_hash': FAKE_VIOLATION_HASH},
    {'inventory_index_id': FAKE_INVENTORY_INDEX_ID,
     'resource_id': 'fake_firewall_222',
     'full_name': 'full_name_222',
     'rule_name': 'disallow_all_ports_222',
     'rule_index': 222,
     'violation_data':
         {'policy_names': ['fw-tag-match_222'],
          'recommended_actions':
              {'DELETE_FIREWALL_RULES': ['fw-tag-match_222']}},
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION_222',
     'resource_type': 'firewall_rule',
     'inventory_data': 'inventory_data_222',
     'violation_hash': FAKE_VIOLATION_HASH},
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
        violation_access_cls = scanner_dao.define_violation(engine)
        violation_access = violation_access_cls(engine)

        violation_access.create(FAKE_EXPECTED_VIOLATIONS,
                                FAKE_INVENTORY_INDEX_ID)
        saved_violations = violation_access.list()

        keys = ['inventory_index_id', 'resource_id', 'full_name',
                'resource_type', 'rule_name', 'rule_index', 'violation_type',
                'violation_data', 'violation_hash', 'inventory_data']
        for fake, saved in izip(FAKE_EXPECTED_VIOLATIONS, saved_violations):
            for key in keys:
                if key != 'violation_data':
                    self.assertEquals(
                        fake.get(key), getattr(saved, key),
                        'The key value of "%s" differs:\nExpected: %s'
                        '\nFound: %s' % (key, fake.get(key),
                                         getattr(saved, key))
                    )
                else:
                    self.assertEquals(
                        fake.get(key), json.loads(getattr(saved,
                                                          'violation_data')),
                        'key %s differs' % key)


    @mock.patch.object(scanner_dao,'_create_violation_hash')
    def test_convert_sqlalchemy_object_to_dict(self, mock_violation_hash):
        mock_violation_hash.side_effect = [FAKE_VIOLATION_HASH,
                                           FAKE_VIOLATION_HASH]
        engine = create_test_engine()
        violation_access_cls = scanner_dao.define_violation(engine)
        violation_access = violation_access_cls(engine)

        violation_access.create(FAKE_EXPECTED_VIOLATIONS,
                                FAKE_INVENTORY_INDEX_ID)
        saved_violations = violation_access.list()

        converted_violations_as_dict = []
        for violation in saved_violations:
            converted_violations_as_dict.append(
                scanner_dao.convert_sqlalchemy_object_to_dict(violation))

        expected_violations_as_dict = [
            {'full_name': u'full_name_111',
             'id': 1,
             'inventory_data': u'inventory_data_111',
             'inventory_index_id': u'aaa',
             'resource_id': u'fake_firewall_111',
             'resource_type': u'firewall_rule',
             'rule_index': 111,
             'rule_name': u'disallow_all_ports_111',
             'violation_data': u'{"policy_names": ["fw-tag-match_111"], "recommended_actions": {"DELETE_FIREWALL_RULES": ["fw-tag-match_111"]}}',
             'violation_type': u'FIREWALL_BLACKLIST_VIOLATION_111',
             'violation_hash': u'11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'},
            {'full_name': u'full_name_222',
             'id': 2,
             'inventory_data': u'inventory_data_222',
             'inventory_index_id': u'aaa',
             'resource_id': u'fake_firewall_222',
             'resource_type': u'firewall_rule',
             'rule_index': 222,
             'rule_name': u'disallow_all_ports_222',
             'violation_data': u'{"policy_names": ["fw-tag-match_222"], "recommended_actions": {"DELETE_FIREWALL_RULES": ["fw-tag-match_222"]}}',
             'violation_hash': u'11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111',
             'violation_type': u'FIREWALL_BLACKLIST_VIOLATION_222'}]

        self.assertEquals(expected_violations_as_dict,
                          converted_violations_as_dict)

        self.assertEquals(mock_violation_hash.call_count,
                          len(FAKE_EXPECTED_VIOLATIONS))


if __name__ == '__main__':
    unittest.main()
