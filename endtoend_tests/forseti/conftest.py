# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

"""Forseti end-to-end test configuration"""

import pytest
import re
import time
from endtoend_tests.helpers.forseti_cli import ForsetiCli
from endtoend_tests.helpers.server_config import ServerConfig


@pytest.fixture(scope="session")
def forseti_cli():
    return ForsetiCli()


@pytest.fixture(scope="session")
def forseti_inventory_readonly(forseti_cli):
    inventory_id, result = forseti_cli.inventory_create()
    yield inventory_id, result
    forseti_cli.inventory_delete(inventory_id)


@pytest.fixture(scope="session")
def forseti_model_readonly(forseti_cli, forseti_inventory_readonly):
    model_name = f'Test{str(int(time.time()))}'
    handle, result = forseti_cli.model_create(forseti_inventory_readonly[0],
                                              model_name)

    yield model_name, handle, result
    forseti_cli.model_delete(model_name)


@pytest.fixture(scope="session")
def forseti_notifier_readonly(forseti_cli, forseti_scan_readonly):
    scanner_id, _ = forseti_scan_readonly
    yield forseti_cli.notifier_run(scanner_index_id=scanner_id)


@pytest.fixture(scope="session")
def forseti_scan_readonly(forseti_cli, forseti_model_readonly):
    forseti_cli.model_use(forseti_model_readonly[0])
    yield forseti_cli.scanner_run()


@pytest.fixture(scope="session")
def server_config_helper(forseti_server_bucket_name, forseti_server_config_path):
    server_config = ServerConfig(forseti_server_config_path)
    yield server_config
    server_config.copy_from_gcs(forseti_server_bucket_name)
