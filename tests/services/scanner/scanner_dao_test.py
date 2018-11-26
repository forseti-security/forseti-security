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

"""Unit Tests for Scanner DAO."""

from datetime import datetime
from datetime import timedelta
import hashlib
from itertools import izip
import json
import os
import unittest
import mock
from sqlalchemy.orm import sessionmaker

from tests.services.scanner import scanner_base_db
from tests.services.util.db import create_test_engine_with_file
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util.index_state import IndexState
from google.cloud.forseti.services.scanner import dao as scanner_dao


# pylint: disable=bad-indentation
class ScannerDaoTest(scanner_base_db.ScannerBaseDbTestCase):
    """Test scanner data access."""

    def setUp(self):
        """Setup method."""
        super(ScannerDaoTest, self).setUp()
        self.maxDiff = None

        # Used in hashing tests.
        self.test_violation_full_name = ''
        self.test_inventory_data = ''
        self.test_violation_data = {}

    def test_save_violations(self):
        """Test violations can be saved."""
        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id1)
        saved_violations = self.violation_access.list(
            scanner_index_id=scanner_index_id)

        expected_hash_values = [
            (u'539cfbdb1113a74ec18edf583eada77ab1a60542c6edcb4120b50f34629b6b69'
             '041c13f0447ab7b2526d4c944c88670b6f151fa88444c30771f47a3b813552ff'
            ),
            (u'3eff279ccb96799d9eb18e6b76055b2242d1f2e6f14c1fb3bb48f7c8c03b4ce4'
             'db577d67c0b91c5914902d906bf1703d5bbba0ceaf29809ac90fef3bf6aa5417'
            ),
        ]

        keys = ['scanner_index_id', 'resource_id', 'full_name',
                'resource_type', 'rule_name', 'rule_index', 'violation_type',
                'violation_data', 'violation_hash', 'resource_data',
                'created_at_datetime']

        for fake, saved in izip(scanner_base_db.FAKE_VIOLATIONS,
                                saved_violations):
            for key in keys:
                if key == 'scanner_index_id':
                    expected_key_value = fake.get(key, scanner_index_id)
                else:
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

    @mock.patch.object(scanner_dao, '_create_violation_hash')
    def test_convert_sqlalchemy_object_to_dict(self, mock_violation_hash):
        mock_violation_hash.side_effect = [
            scanner_base_db.FAKE_VIOLATION_HASH,
            scanner_base_db.FAKE_VIOLATION_HASH
        ]
        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id1)
        saved_violations = self.violation_access.list(
            scanner_index_id=scanner_index_id)

        converted_violations_as_dict = []
        for violation in saved_violations:
            converted_violations_as_dict.append(
                scanner_dao.convert_sqlalchemy_object_to_dict(violation))

        expected_violations_as_dict = [
            {'full_name': u'full_name_111',
             'id': 1,
             'resource_name': 'fw-tag-match_111',
             'resource_data': u'inventory_data_111',
             'scanner_index_id': scanner_index_id,
             'resource_id': u'fake_firewall_111',
             'resource_type': u'firewall_rule',
             'rule_index': 111,
             'rule_name': u'disallow_all_ports_111',
             'violation_data': (
                 u'{"policy_names": ["fw-tag-match_111"], '
                 '"recommended_actions": {"DELETE_FIREWALL_RULES": '
                 '["fw-tag-match_111"]}}'),
             'violation_type': u'FIREWALL_BLACKLIST_VIOLATION_111',
             'violation_hash': scanner_base_db.FAKE_VIOLATION_HASH,
            },
            {'full_name': u'full_name_222',
             'id': 2,
             'resource_name': 'fw-tag-match_222',
             'resource_data': u'inventory_data_222',
             'scanner_index_id': scanner_index_id,
             'resource_id': u'fake_firewall_222',
             'resource_type': u'firewall_rule',
             'rule_index': 222,
             'rule_name': u'disallow_all_ports_222',
             'violation_data': (
                 u'{"policy_names": ["fw-tag-match_222"], '
                 '"recommended_actions": {"DELETE_FIREWALL_RULES": '
                 '["fw-tag-match_222"]}}'),
             'violation_type': u'FIREWALL_BLACKLIST_VIOLATION_222',
             'violation_hash': scanner_base_db.FAKE_VIOLATION_HASH,
            }
        ]

        # It's useless testing 'created_at_datetime' as we can't mock datetime
        # and we only care about its type and not its value.
        for violation in converted_violations_as_dict:
            del violation['created_at_datetime']

        self.assertEqual(expected_violations_as_dict,
                         converted_violations_as_dict)

        self.assertEqual(mock_violation_hash.call_count,
                         len(scanner_base_db.FAKE_VIOLATIONS))

    def test_create_violation_hash_with_default_algorithm(self):
        """Test _create_violation_hash."""
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
        """Test _create_violation_hash with an invalid algorithm."""
        mock_hashlib.side_effect = ValueError

        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            self.test_inventory_data,
            self.test_violation_data)

        self.assertEqual('', returned_hash)

    @mock.patch.object(json, 'dumps')
    def test_create_violation_hash_invalid_violation_data(self, mock_json):
        """Test _create_violation_hash returns '' when it can't hash."""
        expected_hash = ''

        # Mock json.loads has an error, e.g. invalid violation_data data.:w
        mock_json.side_effect = TypeError()

        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            self.test_inventory_data,
            self.test_violation_data)

        self.assertEqual(expected_hash, returned_hash)

    def test_create_violation_hash_with_inventory_data_not_string(self):
        expected_hash = ('fc59c859e9a088d14627f363d629142920225c8b1ea40f2df8b45'
                         '0ff7296c3ad99addd6a1ab31b5b8ffb250e1f25f2a8a6ecf2068a'
                         'fd5f0c46bc2d810f720b9a')
        returned_hash = scanner_dao._create_violation_hash(
            self.test_violation_full_name,
            ['aaa', 'bbb', 'ccc'],
            self.test_violation_data)
        self.assertEquals(expected_hash, returned_hash)

    def test_create_violation_hash_with_full_name_not_string(self):
        expected_hash = ('f8813c34ab225002fb2c04ee392691b4e37c9a0eee1a08b277c36'
                         'b7bb0309f9150a88231dbd3f4ec5e908a5a39a8e38515b8e532d5'
                         '09aa3220e71ab4844a0284')
        returned_hash = scanner_dao._create_violation_hash(
            None,
            self.test_inventory_data,
            self.test_violation_data)
        self.assertEquals(expected_hash, returned_hash)

    def test_get_latest_scanner_index_id_with_empty_table(self):
        """The method under test returns `None` if the table is empty."""
        self.assertIsNone(
            scanner_dao.get_latest_scanner_index_id(self.session, 123))

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_get_latest_scanner_index_id(self, mock_date_time):
        """The method under test returns the newest `ScannerIndex` row."""
        time1 = datetime.utcnow()
        time2 = time1 + timedelta(minutes=5)
        time3 = time1 + timedelta(minutes=7)
        mock_date_time.side_effect = [time1, time2, time3]

        expected_id = date_time.get_utc_now_microtimestamp(time2)

        self.session.add(scanner_dao.ScannerIndex.create(expected_id))
        index2 = scanner_dao.ScannerIndex.create(expected_id)
        index2.scanner_status = IndexState.SUCCESS
        self.session.add(index2)
        self.session.add(scanner_dao.ScannerIndex.create(expected_id))
        self.session.flush()
        self.assertEquals(
            expected_id, scanner_dao.get_latest_scanner_index_id(
                self.session, expected_id))

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_get_latest_scanner_index_id_with_failure_state(self,
                                                            mock_date_time):
        """The method under test returns the newest `ScannerIndex` row."""
        time1 = datetime.utcnow()
        time2 = time1 + timedelta(minutes=5)
        time3 = time1 + timedelta(minutes=7)
        mock_date_time.side_effect = [time1, time2, time3]

        expected_id = date_time.get_utc_now_microtimestamp(time1)

        index1 = scanner_dao.ScannerIndex.create(expected_id)
        index1.scanner_status = IndexState.FAILURE
        self.session.add(index1)
        self.session.add(scanner_dao.ScannerIndex.create(expected_id))
        self.session.add(scanner_dao.ScannerIndex.create(expected_id))
        self.session.flush()
        self.assertEquals(
            expected_id,
            scanner_dao.get_latest_scanner_index_id(
                self.session, expected_id, IndexState.FAILURE))


class ScannerIndexTest(ForsetiTestCase):
    """Test scanner data access."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.engine, self.dbfile = create_test_engine_with_file()
        scanner_dao.ScannerIndex.__table__.create(bind=self.engine)
        session_maker = sessionmaker()
        self.session = session_maker(bind=self.engine)

    def tearDown(self):
        """Teardown method."""
        os.unlink(self.dbfile)
        ForsetiTestCase.tearDown(self)

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_scanner_index_create(self, mock_date_time):
        """`ScannerIndex` create() works as expected."""
        utc_now = datetime.utcnow()
        mock_date_time.return_value = utc_now
        expected_id = date_time.get_utc_now_microtimestamp(utc_now)
        db_row = scanner_dao.ScannerIndex.create(expected_id)
        self.assertEquals(expected_id, db_row.id)
        self.assertEquals(utc_now, db_row.created_at_datetime)
        self.assertEquals(IndexState.CREATED, db_row.scanner_status)

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_scanner_index_complete(self, mock_date_time):
        """`ScannerIndex` complete() works as expected."""
        start = datetime.utcnow()
        end = start + timedelta(minutes=5)
        # ScannerIndex.create() calls get_utc_now_datetime() twice.
        mock_date_time.side_effect = [start, end]
        expected_id = date_time.get_utc_now_microtimestamp(start)

        db_row = scanner_dao.ScannerIndex.create(expected_id)
        self.assertEquals(expected_id, db_row.id)
        db_row.complete()
        self.assertEquals(end, db_row.completed_at_datetime)
        self.assertEquals(IndexState.SUCCESS, db_row.scanner_status)

    def test_scanner_index_add_warning(self):
        """`ScannerIndex` add_warning() works as expected."""
        db_row = scanner_dao.ScannerIndex.create('aaa')
        db_row.add_warning(self.session, '1st warning')
        db_row.add_warning(self.session, '2nd warning')
        self.assertEquals(
            '1st warning\n2nd warning\n', db_row.scanner_index_warnings)

    def test_scanner_index_set_error(self):
        """`ScannerIndex` set_error() works as expected."""
        db_row = scanner_dao.ScannerIndex.create('aaa')
        db_row.set_error(self.session, 'scanner error!')
        self.assertEquals('scanner error!', db_row.scanner_index_errors)


class ViolationListTest(scanner_base_db.ScannerBaseDbTestCase):
    """Test the Violation.list() method."""

    def test_list_without_indices(self):
        self.populate_db(inv_index_id=self.inv_index_id1)
        self.populate_db(inv_index_id=self.inv_index_id2)
        actual_data = self.violation_access.list()
        self.assertEquals(2 * len(scanner_base_db.FAKE_VIOLATIONS),
                          len(actual_data))

    def test_list_with_inv_index_single_successful_scan(self):
        self.populate_db(inv_index_id=self.inv_index_id1)
        actual_data = self.violation_access.list(
            inv_index_id=self.inv_index_id1)
        self.assertEquals(len(scanner_base_db.FAKE_VIOLATIONS),
                          len(actual_data))

    def test_list_with_inv_index_single_failed_scan(self):
        self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        actual_data = self.violation_access.list(
            inv_index_id=self.inv_index_id1)
        self.assertEquals(0, len(actual_data))

    def test_list_with_inv_index_multi_mixed_success_scan(self):
        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id1)
        self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        actual_data = self.violation_access.list(
            inv_index_id=self.inv_index_id1)
        self.assertEquals(len(scanner_base_db.FAKE_VIOLATIONS),
                          len(actual_data))
        for violation in actual_data:
            self.assertEquals(scanner_index_id, violation.scanner_index_id)

    def test_list_with_inv_index_multi_all_success_scan(self):
        self.populate_db(inv_index_id=self.inv_index_id2)
        self.populate_db(inv_index_id=self.inv_index_id2)
        actual_data = self.violation_access.list(
            inv_index_id=self.inv_index_id2)
        self.assertEquals(2 * len(scanner_base_db.FAKE_VIOLATIONS),
                          len(actual_data))

    def test_list_with_inv_index_multi_all_failed_scan(self):
        self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        actual_data = self.violation_access.list(
            inv_index_id=self.inv_index_id1)
        self.assertEquals(0, len(actual_data))

    def test_list_with_scnr_index_single_successful_scan(self):
        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id1)
        actual_data = self.violation_access.list(
            scanner_index_id=scanner_index_id)
        self.assertEquals(len(scanner_base_db.FAKE_VIOLATIONS),
                          len(actual_data))
        for violation in actual_data:
            self.assertEquals(scanner_index_id, violation.scanner_index_id)

    def test_list_with_scnr_index_single_failed_scan(self):
        scanner_index_id = self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        actual_data = self.violation_access.list(
            scanner_index_id=scanner_index_id)
        self.assertEquals(0, len(actual_data))

    def test_list_with_scnr_index_multi_mixed_success_scan(self):
        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id1)
        self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        actual_data = self.violation_access.list(
            scanner_index_id=scanner_index_id)
        self.assertEquals(len(scanner_base_db.FAKE_VIOLATIONS), len(actual_data)
                         )
        for violation in actual_data:
            self.assertEquals(scanner_index_id, violation.scanner_index_id)

    def test_list_with_scnr_index_multi_all_success_scan(self):
        scanner_index_id = self.populate_db(inv_index_id=self.inv_index_id1)
        self.populate_db(inv_index_id=self.inv_index_id3)
        actual_data = self.violation_access.list(
            scanner_index_id=scanner_index_id)
        self.assertEquals(len(scanner_base_db.FAKE_VIOLATIONS), len(actual_data)
                         )
        for violation in actual_data:
            self.assertEquals(scanner_index_id, violation.scanner_index_id)

    def test_list_with_scnr_index_multi_all_failed_scan(self):
        scanner_index_id = self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        self.populate_db(
            inv_index_id=self.inv_index_id2, succeeded=[], failed=['IapScanner']
        )
        actual_data = self.violation_access.list(
            scanner_index_id=scanner_index_id)
        self.assertEquals(0, len(actual_data))

    def test_list_with_both_indices(self):
        scanner_index_id = self.populate_db(
            inv_index_id=self.inv_index_id1, succeeded=[], failed=['IapScanner']
        )
        self.populate_db(
            inv_index_id=self.inv_index_id2, succeeded=[], failed=['IapScanner']
        )
        with self.assertRaises(ValueError):
            self.violation_access.list(
                inv_index_id='blah', scanner_index_id=scanner_index_id)


if __name__ == '__main__':
    unittest.main()
