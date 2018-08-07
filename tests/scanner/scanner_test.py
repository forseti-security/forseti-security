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
"""Scanner runner script test."""

from datetime import datetime, timedelta
import mock
from sqlalchemy.orm import sessionmaker
import unittest

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util.index_state import IndexState
from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.services.scanner import dao as scanner_dao
from tests.services.scanner import scanner_base_db


Session = sessionmaker()


FAKE_GLOBAL_CONFIGS = {
    'db_host': 'foo_host',
    'db_user': 'foo_user',
    'db_name': 'foo_db',
    'email_recipient': 'foo_email_recipient'
}

NO_SCANNERS = {'scanners': [
    {'name': 'bigquery', 'enabled': False},
    {'name': 'bucket_acl', 'enabled': False},
    {'name': 'cloudsql_acl', 'enabled': False},
    {'name': 'iam_policy', 'enabled': False}
]}

TWO_SCANNERS = {'scanners': [
    {'name': 'bigquery', 'enabled': False},
    {'name': 'bucket_acl', 'enabled': True},
    {'name': 'cloudsql_acl', 'enabled': True},
    {'name': 'iam_policy', 'enabled': False}
]}

class ScannerRunnerTest(scanner_base_db.ScannerBaseDbTestCase):

    def setUp(self):
        """Setup method."""
        super(ScannerRunnerTest, self).setUp()

    def tearDown(self):
        """Tear down method."""
        super(ScannerRunnerTest, self).tearDown()

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.iam_rules_engine', autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.bucket_rules_scanner.buckets_rules_engine', autospec=True)
    @mock.patch(
        'google.cloud.forseti.services.base.config.ServiceConfig',
        autospec=True)
    def test_scanner_index_id_can_be_correctly_initialized(
        self, mock_service_config, mock_bucket_rules_engine,
        mock_iam_rules_engine):
        """Test that the 'scanner_index_id' *is* initialized.

        We have 2 runnable scanners. The 'scanner_index_id' should be
        initialized only once though.
        """
        mock_service_config.get_global_config.return_value = FAKE_GLOBAL_CONFIGS
        mock_service_config.get_scanner_config.return_value = TWO_SCANNERS
        mock_service_config.engine = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_scoped_session = mock.MagicMock()
        mock_data_access = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock_scoped_session, mock_data_access)
        mock_data_access.scanner_iter.return_value = []
        with mock.patch.object(scanner, 'init_scanner_index') as init_mock:
            with mock.patch.object(scanner, 'mark_scanner_index_complete') as closing_mock:
                scanner.run('m1', mock.MagicMock(), mock_service_config)
                self.assertTrue(init_mock.called)
                self.assertEquals(1, init_mock.call_count)
                self.assertTrue(closing_mock.called)
                self.assertEquals(1, closing_mock.call_count)

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_init_scanner_index(self, mock_date_time):
        utc_now = datetime.utcnow()
        mock_date_time.return_value = utc_now
        scanner.init_scanner_index(self.session, self.inv_index_id3)
        expected_id = date_time.get_utc_now_microtimestamp(utc_now)
        db_row = (self.session.query(scanner_dao.ScannerIndex)
                  .filter(scanner_dao.ScannerIndex.id == expected_id).one())
        self.assertEquals(IndexState.RUNNING, db_row.scanner_status)
        self.assertEquals(utc_now, db_row.created_at_datetime)

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_mark_scanner_index_complete_no_failures(self, mock_date_time):
        start = datetime.utcnow()
        end = start + timedelta(minutes=5)
        mock_date_time.side_effect = [start, end]

        scanner_index_id = scanner.init_scanner_index(
            self.session, self.inv_index_id2)
        scanner.mark_scanner_index_complete(
            self.session, scanner_index_id, ['IamPolicyScanner'], [])
        db_row = (self.session.query(scanner_dao.ScannerIndex)
                  .filter(scanner_dao.ScannerIndex.id == scanner_index_id).one())
        self.assertEquals(IndexState.SUCCESS, db_row.scanner_status)
        self.assertEquals(end, db_row.completed_at_datetime)

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_mark_scanner_index_complete_only_failures(self, mock_date_time):
        start = datetime.utcnow()
        end = start + timedelta(minutes=5)
        mock_date_time.side_effect = [start, end]

        scanner_index_id = scanner.init_scanner_index(
            self.session, self.inv_index_id2)
        scanner.mark_scanner_index_complete(
            self.session, scanner_index_id, [],
            ['IamPolicyScanner', 'IapScanner'])
        db_row = (self.session.query(scanner_dao.ScannerIndex)
                  .filter(scanner_dao.ScannerIndex.id == scanner_index_id).one())
        self.assertEquals(IndexState.FAILURE, db_row.scanner_status)
        self.assertEquals(
            'Scanner(s) with errors: IamPolicyScanner, IapScanner',
            db_row.scanner_index_errors)
        self.assertEquals(end, db_row.completed_at_datetime)

    @mock.patch.object(date_time, 'get_utc_now_datetime')
    def test_mark_scanner_index_complete_with_partial_failures(self, mock_date_time):
        start = datetime.utcnow()
        end = start + timedelta(minutes=5)
        mock_date_time.side_effect = [start, end]

        scanner_index_id = scanner.init_scanner_index(
            self.session, self.inv_index_id1)
        scanner.mark_scanner_index_complete(
            self.session, scanner_index_id, ['KeVersionScanner'],
            ['IamPolicyScanner', 'IapScanner'])
        db_row = (self.session.query(scanner_dao.ScannerIndex)
                  .filter(scanner_dao.ScannerIndex.id == scanner_index_id).one())
        self.assertEquals(IndexState.PARTIAL_SUCCESS, db_row.scanner_status)
        self.assertEquals(
            'Scanner(s) with errors: IamPolicyScanner, IapScanner',
            db_row.scanner_index_errors)
        self.assertEquals(end, db_row.completed_at_datetime)


if __name__ == '__main__':
    unittest.main()
