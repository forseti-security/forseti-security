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

"""KMS Scanner Tests."""

import unittest
import mock
from datetime import datetime

from tests import unittest_utils
from tests.services.util.db import create_test_engine
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.scanner.scanners import kms_scanner
from google.cloud.forseti.common.util.string_formats import TIMESTAMP_MICROS
from google.cloud.forseti.services.dao import ModelManager


"""
Assumptions: In data/kms_scanner_test_rules.yaml, rotation_period is set to
100 days.

Test: Create two crypto keys, one with creation time over 100 days ago, and
other with creation time less than 100 days ago.

The crypto key with creation time over 100 days ago should be flagged as a
violation but not the other one.
"""

TIME_NOW = datetime.utcnow()

'''
class FakeServiceConfig(object):

    def __init__(self):
        engine = create_test_engine()
        self.model_manager = ModelManager(engine)

class KMSScannerTest(unittest_utils.ForsetiTestCase):

    @classmethod
    def setUpClass(cls):
        cls.service_config = FakeServiceConfig()
        cls.model_name = cls.service_config.model_manager.create(
            name='kms-scanner-test')

        scoped_session, data_access = (
            cls.service_config.model_manager.get(cls.model_name)

        # Add organization to model.
        with scoped_session as session:
            organization = data.access.add.resource_by_name(
        session, 'organization/12345', '', True)


        session.commit()


    def setUp(self):
        self.scanner = kms_scanner.KKMSScanner(
            {}, {}, self.service_config, self.model_name,
            '', unittest_utils.get_datafile_path(
                __file__, 'kms_scanner_test_rules.yaml'))

    @mock.patch.object(
        kms_scanner.KKMSScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        expected_violations = [EXPECTED_VIOLATION, ]
        mock_output_results.assert_called_once_with(mock.ANY,
                                                    expected_violations)

    def test_retrieve(self):
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        mock_rule_book = mock.MagicMock()
        mock_rule_book.get_applicable_resource_types.return_value = set([
            'organization'])
        self.scanner.rules_engine.rule_book = mock_rule_book


        got = set(self.scanner._retrieve())
        want = {data.BUCKET, data.PROJECT1}
        self.assertEqual(got, want)

'''

if __name__ == '__main__':
    unittest.main()
