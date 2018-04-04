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
import unittest
import mock

from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.scanner import scanner
from google.cloud.forseti.scanner.scanners.base_scanner import BaseScanner
from tests.unittest_utils import ForsetiTestCase

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

ONE_SCANNER = {'scanners': [
    {'name': 'bigquery', 'enabled': False},
    {'name': 'bucket_acl', 'enabled': False},
    {'name': 'cloudsql_acl', 'enabled': False},
    {'name': 'iam_policy', 'enabled': True}
]}

class ScannerRunnerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.services.server.ServiceConfig', autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanner.scanner_builder', autospec=True)
    def test_no_runnable_scanners(
        self, mock_scanner_builder_module, mock_service_config):
        """Test that the scanner_index_id is not initialized."""
        mock_service_config.get_global_config.return_value = FAKE_GLOBAL_CONFIGS
        mock_service_config.get_scanner_config.return_value = NO_SCANNERS
        mock_service_config.engine = mock.MagicMock()
        mock_scanner_builder = mock.MagicMock()
        mock_scanner_builder_module.ScannerBuilder.return_value = (
            mock_scanner_builder)
        mock_scanner_builder.build.return_value = []
        with mock.patch.object(BaseScanner, "init_scanner_index_id") as mock_initializer:
            scanner.run('m1', mock.MagicMock(), mock_service_config)
            self.assertFalse(mock_initializer.called)

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.iam_rules_scanner.iam_rules_engine', autospec=True)
    @mock.patch(
        'google.cloud.forseti.services.server.ServiceConfig', autospec=True)
    def test_with_runnable_scanners(
        self, mock_service_config, mock_iam_rules_engine):
        """Test that the scanner_index_id *is* initialized."""
        mock_service_config.get_global_config.return_value = FAKE_GLOBAL_CONFIGS
        mock_service_config.get_scanner_config.return_value = ONE_SCANNER
        mock_service_config.engine = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_scoped_session = mock.MagicMock()
        mock_data_access = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock_scoped_session, mock_data_access)
        mock_data_access.scanner_iter.return_value = []
        with mock.patch.object(BaseScanner, "init_scanner_index_id") as mock_initializer:
            scanner.run('m1', mock.MagicMock(), mock_service_config)
            self.assertTrue(mock_initializer.called)
            self.assertEquals(1, mock_initializer.call_count)


if __name__ == '__main__':
    unittest.main()
