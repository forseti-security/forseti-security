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

from datetime import datetime
import hashlib

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
    },
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
     }
]


class ScannerDaoTest(ForsetiTestCase):
    """Test scanner data access."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.maxDiff = None

        # Used in hashing tests.
        self.test_violation_full_name = ''
        self.test_inventory_data = ''
        self.test_violation_data = {}

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

        expected_hash_values = [
          (u'539cfbdb1113a74ec18edf583eada77ab1a60542c6edcb4120b50f34629b6b6904'
            '1c13f0447ab7b2526d4c944c88670b6f151fa88444c30771f47a3b813552ff'),
          (u'3eff279ccb96799d9eb18e6b76055b2242d1f2e6f14c1fb3bb48f7c8c03b4ce4db'
            '577d67c0b91c5914902d906bf1703d5bbba0ceaf29809ac90fef3bf6aa5417')
        ]

        keys = ['inventory_index_id', 'resource_id', 'full_name',
                'resource_type', 'rule_name', 'rule_index', 'violation_type',
                'violation_data', 'violation_hash', 'inventory_data',
                'created_at_datetime']

        for fake, saved in izip(FAKE_EXPECTED_VIOLATIONS, saved_violations):
            for key in keys:
                expected_key_value = fake.get(key)
                saved_key_value = getattr(saved, key)
                if key == 'violation_data':
                    self.assertEquals(
                        expected_key_value,
                        json.loads(saved_key_value),
                        'The key value of "%s" differs:\nExpected: %s'
                        '\nFound: %s' % (key, expected_key_value,
                                         saved_key_value)
                    )
                elif key == 'violation_hash':
                    self.assertIn(
                        saved_key_value, expected_hash_values,
                        'The key value of "%s" differs:\nExpected one of: %s'
                        '\nFound: %s' % (key, ',\n'.join(expected_hash_values),
                                         saved_key_value)
                    )
                elif key == 'created_at_datetime':
                    self.assertIsInstance(
                        saved_key_value, datetime,
                        'The key value of "%s" differs:\n Expected type: %s'
                        '\nFound type: %s' % (key, type(datetime),
                                              type(saved_key_value))
                    )
                else:
                    self.assertEquals(
                        expected_key_value, saved_key_value,
                        'The key value of "%s" differs:\nExpected: %s'
                        '\nFound: %s' % (key, expected_key_value,
                                         saved_key_value)
                    )

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
             'violation_hash': FAKE_VIOLATION_HASH,
            },
            {'full_name': u'full_name_222',
             'id': 2,
             'inventory_data': u'inventory_data_222',
             'inventory_index_id': u'aaa',
             'resource_id': u'fake_firewall_222',
             'resource_type': u'firewall_rule',
             'rule_index': 222,
             'rule_name': u'disallow_all_ports_222',
             'violation_data': u'{"policy_names": ["fw-tag-match_222"], "recommended_actions": {"DELETE_FIREWALL_RULES": ["fw-tag-match_222"]}}',
             'violation_type': u'FIREWALL_BLACKLIST_VIOLATION_222',
             'violation_hash': FAKE_VIOLATION_HASH,
            }
        ]

        # It's useless testing 'created_at_datetime' as we can't mock datetime
        # and we only care about its type and not its value.
        for violation in converted_violations_as_dict:
            del violation['created_at_datetime']

        self.assertEqual(expected_violations_as_dict,
                         converted_violations_as_dict)

        self.assertEqual(mock_violation_hash.call_count,
                         len(FAKE_EXPECTED_VIOLATIONS))

    def test_create_violation_hash_with_default_algorithm(self):
        """ Test _create_violation_hash. """
        test_hash = hashlib.new('sha512')
        test_hash.update(
            json.dumps(self.test_violation_full_name) +
            json.dumps(self.test_inventory_data) +
            json.dumps(self.test_violation_data)
        )
        expected_hash = test_hash.hexdigest()

        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            self.test_inventory_data,
            self.test_violation_data)

        self.assertEqual(expected_hash, returned_hash)

    @mock.patch.object(hashlib, 'new')
    def test_create_violation_hash_with_invalid_algorithm(self, mock_hashlib):
        """ Test _create_violation_hash with an invalid algorithm. """
        mock_hashlib.side_effect = ValueError

        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            self.test_inventory_data,
            self.test_violation_data)

        self.assertEqual('', returned_hash)

    @mock.patch.object(json, 'dumps')
    def test_create_violation_hash_invalid_violation_data(self, mock_json):
        """ Test _create_violation_hash returns '' when it can't hash. """
        expected_hash = ''

        # Mock json.loads has an error, e.g. invalid violation_data data.:w
        mock_json.side_effect = TypeError()

        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            self.test_inventory_data,
            self.test_violation_data)

        self.assertEqual(expected_hash, returned_hash)

    def test_create_violation_hash_with_inventory_data_not_string(self):
        expected_hash = 'fc59c859e9a088d14627f363d629142920225c8b1ea40f2df8b450ff7296c3ad99addd6a1ab31b5b8ffb250e1f25f2a8a6ecf2068afd5f0c46bc2d810f720b9a'
        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            ['aaa', 'bbb', 'ccc'],
            self.test_violation_data)                                                  
        self.assertEquals(expected_hash, returned_hash)

    def test_create_violation_hash_with_full_name_not_string(self):
        expected_hash = 'f8813c34ab225002fb2c04ee392691b4e37c9a0eee1a08b277c36b7bb0309f9150a88231dbd3f4ec5e908a5a39a8e38515b8e532d509aa3220e71ab4844a0284'
        returned_hash = scanner_dao._create_violation_hash(
            None,
            self.test_inventory_data,
            self.test_violation_data)                                                  
        self.assertEquals(expected_hash, returned_hash)

if __name__ == '__main__':
    unittest.main()
