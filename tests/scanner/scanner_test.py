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

from datetime import datetime
import mock
from sqlalchemy.orm import sessionmaker
import unittest

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.services.scanner.dao import (
    ScannerIndex, ScannerState)
from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase


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
    {'name': 'cloudsql_acl', 'enabled': False},
    {'name': 'iam_policy', 'enabled': True}
]}

class ScannerRunnerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.iam_rules_engine', autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanners.bucket_rules_scanner.buckets_rules_engine', autospec=True)
    @mock.patch(
        'google.cloud.forseti.services.server.ServiceConfig', autospec=True)
    def test_with_runnable_scanners(
        self, mock_service_config, mock_bucket_rules_engine,
        mock_iam_rules_engine):
        """Test that the 'scanner_start_time' *is* initialized.

        We have 2 runnable scanners. The 'scanner_start_time' should be
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
        with mock.patch.object(scanner, 'init_scanner_index') as mock_initializer:
            scanner.run('m1', mock.MagicMock(), mock_service_config)
            self.assertTrue(mock_initializer.called)
            self.assertEquals(1, mock_initializer.call_count)

    @mock.patch(
        'google.cloud.forseti.services.scanner.dao.date_time',
        autospec=True)
    @mock.patch(
        'google.cloud.forseti.services.server.ServiceConfig', autospec=True)
    def test_init_scanner_index(self, mock_service_config, mock_date_time):
        mock_service_config.engine = create_test_engine()
        utc_now = datetime.utcnow()
        mock_date_time.get_utc_now_datetime.return_value = utc_now
        scanner.init_scanner_index(mock_service_config)
        session = Session(bind=mock_service_config.engine)
        expected_id = utc_now.strftime(string_formats.TIMESTAMP_MICROS)
        db_row = (session.query(ScannerIndex)
                  .filter(ScannerIndex.id == expected_id).one())
        self.assertEquals(ScannerState.CREATED, db_row.scanner_status)


if __name__ == '__main__':
    unittest.main()
