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

"""Tests the Forseti Server inventory service."""

import mock
import os
import time
import unittest

from tests.services.api_tests.api_tester import ApiTestRunner
from tests.services.utils.db import cleanup
from tests.services.utils.db import create_test_engine
from tests.services.utils.mock import MockServerConfig
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.auditor import rules_engine
from google.cloud.forseti.auditor.rules import rule
from google.cloud.forseti.common.util.threadpool import ThreadPool
from google.cloud.forseti.services import client
from google.cloud.forseti.services import db
from google.cloud.forseti.services.auditor import storage
from google.cloud.forseti.services.auditor.service import GrpcAuditorFactory
from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.model.service import GrpcModellerFactory
from google.cloud.forseti.services.playground.service import GrpcPlaygrounderFactory


TEST_RULES_PATH = os.path.abspath(
    os.path.join(__file__, '..', '..', '..',
                 'auditor', 'test_data', 'test_valid_rules1.yaml')
)


class TestServiceConfig(MockServerConfig):
    """ServiceConfig Stub."""

    def __init__(self):
        self.engine = create_test_engine()
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)

    def run_in_background(self, function):
        """Stub."""
        function()
        return self

    def get_engine(self):
        return self.engine

    def scoped_session(self):
        return self.sessionmaker()


def create_tester():
    """Create API test runner."""

    test_config = TestServiceConfig()

    return ApiTestRunner(
        TestServiceConfig(),
        [GrpcExplainerFactory,
         GrpcPlaygrounderFactory,
         GrpcInventoryFactory,
         GrpcModellerFactory,
         GrpcAuditorFactory])


class AuditorApiTest(ForsetiTestCase):
    """Auditor API Test."""

    def setUp(self):
        self.setup = create_tester()

    @mock.patch('google.cloud.forseti.common.util.file_loader.read_and_parse_file', autospec=True)
    @mock.patch.object(rules_engine.RulesEngine, 'evaluate_rules')
    @mock.patch('google.cloud.forseti.services.auditor.storage.initialize', autospec=True)
    @mock.patch.object(storage.DataAccess, 'create_rule_snapshot', autospec=True)
    @mock.patch.object(storage.DataAccess, 'create_audit', autospec=True)
    def test_auditor_run(self,
                         mock_data_access_create_audit,
                         mock_data_access_rule_snapshot,
                         mock_storage_init,
                         mock_rules_engine_eval,
                         mock_file_loader):
        """Test: run Auditor."""

        @cleanup
        def test(client):
            """API test callback."""
            progress = None
            audit = None
            model1 = client.new_model('empty', name='test')
            client.switch_model(model1.model.handle)

            mock_file_loader.side_effect = [
                {'auditor':
                 {'rules_path': TEST_RULES_PATH}},
            ]
            mock_data_access_create_audit.return_value = mock.MagicMock()
            mock_data_access_create_audit.return_value.id = 1
            mock_data_access_rule_snapshot.return_value = {
                'xyz': 1
            }
            fake_rule = rule.Rule(rule_name='test')
            mock_rules_engine_eval.return_value = [
                (fake_rule, True)
            ]

            for progress in client.auditor.run():
                continue
            self.assertTrue(progress.final_message)

        self.setup.run(test)


if __name__ == '__main__':
    unittest.main()
