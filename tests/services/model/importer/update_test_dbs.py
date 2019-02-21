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
import mock

from tests.services.api_tests.api_tester import ApiTestRunner
from tests.services.inventory import gcp_api_mocks
from tests.services.model.importer import importer_test
from tests.services.util.db import create_test_engine_with_file
from tests.services.util.mock import MockServerConfig
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util.threadpool import ThreadPool
from google.cloud.forseti.services import db
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.client import ClientComposition
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.inventory.storage import Storage

TEST_RESOURCE_DIR_PATH = os.path.join(
    os.path.dirname(__file__), '../', '../', 'inventory', 'test_data')


class TestServiceConfig(MockServerConfig):
    """ServiceConfig Stub."""

    def __init__(self, engine):
        self.engine = engine
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.workers = ThreadPool(1)
        self.inventory_config = InventoryConfig(gcp_api_mocks.ORGANIZATION_ID,
                                                '',
                                                {},
                                                0,
                                                {'enabled': True,
                                                 'gcs_path': 'gs://test-bucket'}
                                               )
        self.inventory_config.set_service_config(self)

    def run_in_background(self, func):
        """Stub."""
        self.workers.add_func(func)

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


class TestCompositeServiceConfig(TestServiceConfig):
    """Composite root ServiceConfig Stub."""

    def __init__(self, engine):
        self.engine = engine
        self.model_manager = ModelManager(self.engine)
        self.sessionmaker = db.create_scoped_sessionmaker(self.engine)
        self.workers = ThreadPool(1)
        self.inventory_config = InventoryConfig(
            None,
            '',
            {},
            0,
            {'enabled': False},
            ['folders/1032', 'projects/1041'])
        self.inventory_config.set_service_config(self)


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

    fake_time = importer_test.FAKE_DATETIME
    _ = mock.patch.object(
        date_time,
        'get_utc_now_datetime',
        return_value=fake_time).start()

    # Ensure test data doesn't get deleted
    mock_unlink = mock.patch.object(
        os, 'unlink', autospec=True).start()
    mock_copy_file_from_gcs = mock.patch.object(
        file_loader,
        'copy_file_from_gcs',
        autospec=True).start()

    # Mock copy_file_from_gcs to return correct test data file
    def _copy_file_from_gcs(file_path, *args, **kwargs):
        """Fake copy_file_from_gcs."""
        if 'resource' in file_path:
            return os.path.join(TEST_RESOURCE_DIR_PATH,
                                'mock_cai_resources.dump')
        elif 'iam_policy' in file_path:
            return os.path.join(TEST_RESOURCE_DIR_PATH,
                                'mock_cai_iam_policies.dump')

    mock_copy_file_from_gcs.side_effect = _copy_file_from_gcs

    engine, tmpfile = create_test_engine_with_file()
    config = TestServiceConfig(engine)

    with gcp_api_mocks.mock_gcp():
        runner = ApiTestRunner(config, [GrpcInventoryFactory])
        runner.run(create_inventory)
        time.sleep(5)

    copy_db_file_to_test(tmpfile, 'forseti-test.db')

    engine, tmpfile = create_test_engine_with_file()
    config = TestCompositeServiceConfig(engine)

    with gcp_api_mocks.mock_gcp():
        runner = ApiTestRunner(config, [GrpcInventoryFactory])
        runner.run(create_inventory)
        time.sleep(5)

    copy_db_file_to_test(tmpfile, 'forseti-composite-test.db')


if __name__ == '__main__':
    main()
