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

"""Tests the IAM Explain inventory."""

import time
import unittest
from tests.services.inventory import gcp_api_mocks
from tests.services.api_tests.api_tester import ApiTestRunner
from tests.services.utils.db import create_test_engine
from tests.services.utils.mock import MockServerConfig
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util.threadpool import ThreadPool
from google.cloud.forseti.services import db
from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.inventory.storage import Storage
from google.cloud.forseti.services.playground.service import GrpcPlaygrounderFactory
from google.cloud.forseti.services.server import InventoryConfig


class TestServiceConfig(MockServerConfig):
    """ServiceConfig Stub."""

    def __init__(self):
        self.engine = create_test_engine()
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.workers = ThreadPool(10)
        self.inventory_config = InventoryConfig(gcp_api_mocks.ORGANIZATION_ID,
                                                '',
                                                '')

    def run_in_background(self, function):
        """Stub."""
        self.workers.add_func(function)

    def get_engine(self):
        return self.engine

    def scoped_session(self):
        return self.sessionmaker()

    def client(self):
        return ClientComposition(self.endpoint)

    def get_storage_class(self):
        return Storage

    def get_inventory_config(self):
        return self.inventory_config


def create_tester():
    """Create API test runner."""

    return ApiTestRunner(
        TestServiceConfig(),
        [GrpcExplainerFactory,
         GrpcPlaygrounderFactory,
         GrpcInventoryFactory])


class ApiTest(ForsetiTestCase):
    """Api Test."""

    def test_basic(self):
        """Test: Create inventory, foreground & no import."""

        def test(client):
            """API test callback."""
            progress = None
            inventory_index = None

            for progress in client.inventory.create(background=False,
                                                    import_as=''):
                continue
            self.assertTrue(progress.final_message)

            self.assertGreater(len([x for x in client.inventory.list()]),
                               0,
                               'Assert list not empty')
            for inventory_index in client.inventory.list():
                self.assertTrue(inventory_index.id == progress.id)

            self.assertEqual(inventory_index,
                             (client.inventory.get(inventory_index.id)
                              .inventory))

            self.assertEqual(inventory_index,
                             (client.inventory.delete(inventory_index.id)
                              .inventory))

            self.assertEqual([], [i for i in client.inventory.list()])

        with gcp_api_mocks.mock_gcp():
            setup = create_tester()
            setup.run(test)

    def test_basic_background(self):
        """Test: Create inventory, background & no import."""

        def test(client):
            """API test callback."""
            progress = None
            inventory_index = None

            for progress in client.inventory.create(background=True,
                                                    import_as=''):
                continue
            self.assertTrue(progress.final_message)

            while True:
                # Give background running time to complete.
                time.sleep(2)
                if [x for x in client.inventory.list()]:
                    break

            self.assertGreater(len([x for x in client.inventory.list()]),
                               0,
                               'Assert list not empty')
            for inventory_index in client.inventory.list():
                self.assertTrue(inventory_index.id == progress.id)

            self.assertEqual(inventory_index,
                             (client.inventory.get(inventory_index.id)
                              .inventory))

            self.assertEqual(inventory_index,
                             (client.inventory.delete(inventory_index.id)
                              .inventory))

            self.assertEqual([], [i for i in client.inventory.list()])

        with gcp_api_mocks.mock_gcp():
            setup = create_tester()
            setup.run(test)


if __name__ == '__main__':
    unittest.main()
