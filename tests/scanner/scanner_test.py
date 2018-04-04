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


class ScannerRunnerTest(ForsetiTestCase):

    FAKE_GLOBAL_CONFIGS = {
        'db_host': 'foo_host',
        'db_user': 'foo_user',
        'db_name': 'foo_db',
        'email_recipient': 'foo_email_recipient'
    }

    FAKE_SCANNER_CONFIGS = {'output_path': 'foo_output_path'}

    def setUp(self):
        fake_utcnow = datetime(
            year=1900, month=9, day=8, hour=7, minute=6, second=5,
            microsecond=4)
        self.fake_utcnow = fake_utcnow
        self.fake_utcnow_str = self.fake_utcnow.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

    @mock.patch(
        'google.cloud.forseti.services.server.ServiceConfig', autospec=True)
    @mock.patch(
        'google.cloud.forseti.scanner.scanner.scanner_builder', autospec=True)
    def test_no_runnable_scanners(
        self, mock_scanner_builder_module, mock_service_config):
        """Test that the scanner_index_id is not initialized."""
        import pdb; pdb.set_trace()
        mock_service_config.get_global_config.return_value = (
            self.FAKE_GLOBAL_CONFIGS)
        mock_service_config.get_scanner_config.return_value = (
            self.FAKE_SCANNER_CONFIGS)
        mock_service_config.engine = mock.MagicMock()
        mock_scanner_builder = mock.MagicMock()
        mock_scanner_builder_module.ScannerBuilder.return_value = (
            mock_scanner_builder)
        mock_scanner_builder.build.return_value = []
        with mock.patch.object(BaseScanner, "initialize_scanner_index_id") as mock_initializer:
            scanner.run('m1', mock.MagicMock(), mock_service_config)
            self.assertFalse(mock_initializer.called)


if __name__ == '__main__':
    unittest.main()
