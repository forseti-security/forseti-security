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
from endtoend_tests.helpers.server_config import ServerConfig


@pytest.fixture(scope="session")
def server_config_helper(forseti_server_bucket_name, forseti_server_config_path):
    server_config = ServerConfig(forseti_server_config_path)
    yield server_config
    server_config.copy_from_gcs(forseti_server_bucket_name)
