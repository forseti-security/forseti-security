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
import json
from datetime import datetime

from tests import unittest_utils
from tests.services.util.db import create_test_engine
from tests.scanner.test_data import fake_kms_scanner_data
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

KEY_RING_ID = '4063867491605246570'
CRYPTO_KEY_ID = '12873861500163377322'
CRYPTO_KEY_ID_1 = '12873861500163377324'
CRYPTO_KEY_ID_2 = '12873861500163377326'
VIOLATION_TYPE = 'CRYPTO_KEY_VIOLATION'

TIME_NOW = datetime.utcnow()


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
            cls.service_config.model_manager.get(cls.model_name))

        # Add organization to model.
        with scoped_session as session:
            organization = data_access.add_resource_by_name(
                session, 'organization/12345', '', True)

            project = data_access.add_resource(session, 'project/foo',
                                               organization)

            key_ring = data_access.add_resource(
                session, 'kms_keyring/%s' % KEY_RING_ID, project)

            key_ring.data = fake_kms_scanner_data.KEY_RING_DATA

            crypto_key = data_access.add_resource(
                session, 'kms_cryptokey/%s' % CRYPTO_KEY_ID, key_ring)

            crypto_key.data = fake_kms_scanner_data.NON_ROTATED_CRYPTO_KEY_DATA

            crypto_key_1 = data_access.add_resource(
                session, 'kms_cryptokey/%s' % CRYPTO_KEY_ID_1, key_ring)

            crypto_key_1.data = fake_kms_scanner_data.ROTATED_CRYPTO_KEY_DATA

            crypto_key_2 = data_access.add_resource(
                session, 'kms_cryptokey/%s' % CRYPTO_KEY_ID_2, key_ring)

            crypto_key_2.data = (fake_kms_scanner_data.
                                 NON_ROTATED_CRYPTO_KEY_DESTROYED_STATE_DATA)

            session.commit()

    def setUp(self):
        self.scanner = kms_scanner.KMSScanner(
            {}, {}, self.service_config, self.model_name,
            '', unittest_utils.get_datafile_path(
                __file__, 'kms_scanner_test_rules.yaml'))

    @mock.patch.object(
        kms_scanner.KMSScanner,
        '_output_results_to_db', autospec=True)
    def test_run_scanner(self, mock_output_results):
        self.scanner.run()
        crypto_key = self.scanner._retrieve()
        violations = self.scanner._find_violations(crypto_key)
        for violation in violations:
            state = violation.primary_version.get('state')
            self.assertEquals(state, 'ENABLED')
            self.assertEquals(violation.resource_type, 'kms_cryptokey')
            self.assertEquals(violation.violation_type, VIOLATION_TYPE)
        self.assertEquals(1, mock_output_results.call_count)


if __name__ == '__main__':
    unittest.main()
