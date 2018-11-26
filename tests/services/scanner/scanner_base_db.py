"""Helper base class for testing scanners."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from datetime import datetime
from datetime import timedelta
import os
import mock
from sqlalchemy.orm import sessionmaker

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.services.inventory import storage
from google.cloud.forseti.services.scanner import dao as scanner_dao
from tests.services.util.db import create_test_engine_with_file
from tests.unittest_utils import ForsetiTestCase

FAKE_INV_INDEX_ID = 'aaa'
FAKE_VIOLATION_HASH = (u'111111111111111111111111111111111111111111111111111111'
                       '111111111111111111111111111111111111111111111111111111'
                       '11111111111111111111')

FAKE_VIOLATIONS = [
    {'resource_id': 'fake_firewall_111',
     'full_name': 'full_name_111',
     'rule_name': 'disallow_all_ports_111',
     'rule_index': 111,
     'violation_data':
         {'policy_names': ['fw-tag-match_111'],
          'recommended_actions':
              {'DELETE_FIREWALL_RULES': ['fw-tag-match_111']}},
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION_111',
     'resource_type': 'firewall_rule',
     'resource_data': 'inventory_data_111',
     'resource_name': 'fw-tag-match_111',
    },
    {'resource_id': 'fake_firewall_222',
     'full_name': 'full_name_222',
     'rule_name': 'disallow_all_ports_222',
     'rule_index': 222,
     'violation_data':
         {'policy_names': ['fw-tag-match_222'],
          'recommended_actions':
              {'DELETE_FIREWALL_RULES': ['fw-tag-match_222']}},
     'violation_type': 'FIREWALL_BLACKLIST_VIOLATION_222',
     'resource_type': 'firewall_rule',
     'resource_data': 'inventory_data_222',
     'resource_name': 'fw-tag-match_222',
    }
]


# pylint: disable=bad-indentation
class ScannerBaseDbTestCase(ForsetiTestCase):
    """Base class for database centric tests."""

    def setUp(self):
        """Setup method."""
        ForsetiTestCase.setUp(self)
        self.engine, self.dbfile = create_test_engine_with_file()
        session_maker = sessionmaker()
        self.session = session_maker(bind=self.engine)
        storage.initialize(self.engine)
        scanner_dao.initialize(self.engine)
        self.session.flush()
        self.violation_access = scanner_dao.ViolationAccess(self.session)
        self.inv_index_id1, self.inv_index_id2, self.inv_index_id3 = (
            _setup_inv_indices(self.session))

    def tearDown(self):
        """Teardown method."""
        os.unlink(self.dbfile)
        ForsetiTestCase.tearDown(self)

    def populate_db(
        self, violations=FAKE_VIOLATIONS, inv_index_id=FAKE_INV_INDEX_ID,
        scanner_index_id=None, succeeded=['IamPolicyScanner'], failed=[]):
        """Populate the db with violations.

        Args:
            violations (dict): the violations to write to the test database
            inv_index_id (str): the inventory index to use
            scanner_index_id (str): the scanner index to use
            succeeded (list): names of scanners that ran successfully
            failed (list): names of scanners that failed
        """
        if not scanner_index_id:
            scanner_index_id = scanner.init_scanner_index(
                self.session, inv_index_id)
        self.violation_access.create(violations, scanner_index_id)
        scanner.mark_scanner_index_complete(
            self.session, scanner_index_id, succeeded, failed)
        return scanner_index_id


def _setup_inv_indices(session):
    """The method under test returns the newest `ScannerIndex` row."""
    with mock.patch.object(date_time, 'get_utc_now_datetime') as mock_date_time:
      time1 = datetime.utcnow()
      time2 = time1 + timedelta(minutes=5)
      time3 = time1 + timedelta(minutes=7)
      mock_date_time.side_effect = [time1, time2, time3]

      iidx1 = storage.InventoryIndex.create()
      iidx2 = storage.InventoryIndex.create()
      iidx3 = storage.InventoryIndex.create()
      session.add(iidx1)
      session.add(iidx2)
      session.add(iidx3)
      session.flush()

    return (iidx1.id, iidx2.id, iidx3.id)
