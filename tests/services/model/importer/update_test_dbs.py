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
"""Update test_data databases with new resources.

When the inventory mock_gcp_results.py file is updated, then this script should
be run to update the forseti-test.db file with the additional resources.

From the top forseti-security dir, run:

PYTHONPATH=. python tests/services/model/importer/update_test_dbs.py

"""

import os
import shutil
import time
from tests.services.api_tests.api_tester import ApiTestRunner
from tests.services.inventory import gcp_api_mocks
from tests.services.utils.db import create_test_engine_with_file
from tests.services.utils.mock import MockServerConfig
from google.cloud.forseti.common.util.threadpool import ThreadPool
from google.cloud.forseti.services import db
from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.inventory.storage import Storage
from google.cloud.forseti.services.server import InventoryConfig


class TestServiceConfig(MockServerConfig):
    """ServiceConfig Stub."""

    def __init__(self, engine):
        self.engine = engine
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


def copy_db_file_to_test(tmpfile, db_name):
    module_dir = os.path.dirname(os.path.abspath(__file__))
    test_file = os.path.join(module_dir, 'test_data', db_name)
    shutil.copyfile(tmpfile, test_file)


def main():
    """Create inventory and copy to test_data."""

    def create_inventory(client):
        """Create inventory from mock data."""

        for progress in client.inventory.create(background=False,
                                                import_as=''):
            continue

    engine, tmpfile = create_test_engine_with_file()
    config = TestServiceConfig(engine)

    with gcp_api_mocks.mock_gcp():
        runner = ApiTestRunner(config, [GrpcInventoryFactory])
        runner.run(create_inventory)
        time.sleep(3)

    copy_db_file_to_test(tmpfile, 'forseti-test.db')


if __name__ == '__main__':
    main()
