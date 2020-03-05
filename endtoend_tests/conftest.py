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
import time
from sqlalchemy import create_engine

CLOUDSQL_PORT = 3306
FORSETI_SERVER_CONFIG_PATH = (
    '/home/ubuntu/forseti-security/configs/forseti_conf_server.yaml')


def pytest_addoption(parser):
    parser.addoption('--cai_dump_file_gcs_paths',
                     default='',
                     help='CAI dump file paths for inventory performance test')
    parser.addoption('--cloudsql_instance_name',
                     help='Cloud SQL instance name')
    parser.addoption('--cloudsql_password', help='Cloud SQL password')
    parser.addoption('--cloudsql_port',
                     default=CLOUDSQL_PORT,
                     help='Cloud SQL port')
    parser.addoption('--cloudsql_username', help='Cloud SQL username')
    parser.addoption('--forseti_server_bucket_name',
                     help='Forseti server bucket name')
    parser.addoption('--forseti_server_config_path',
                     default=FORSETI_SERVER_CONFIG_PATH,
                     help='Path to Forseti server config')
    parser.addoption('--forseti_server_vm_name', help='Forseti server VM name')
    parser.addoption('--root_resource_id',
                     help='Root resource id for inventory performance test')


def pytest_configure(config):
    config.addinivalue_line(
        'markers', 'e2e: mark test to run only on named environment'
    )
    config.addinivalue_line(
        'markers', 'inventory: mark to run all inventory tests'
    )
    config.addinivalue_line(
        'markers', 'scanner: mark to run all scanner tests'
    )


@pytest.fixture
def cai_dump_file_gcs_paths(request):
    path = request.config.getoption('--cai_dump_file_gcs_paths')
    path = path.replace('[', '').replace(']', '')
    path = path.replace("'", '').replace(' ', '')
    return path.split(',')


@pytest.fixture
def cloudsql_connection(cloudsql_password, cloudsql_port, cloudsql_username):
    yield create_engine(f'mysql+pymysql://{cloudsql_username}:{cloudsql_password}@127.0.0.1:{cloudsql_port}')


@pytest.fixture
def cloudsql_instance_name(request):
    return request.config.getoption('--cloudsql_instance_name')


@pytest.fixture
def cloudsql_password(request):
    return request.config.getoption('--cloudsql_password')


@pytest.fixture
def cloudsql_port(request):
    return request.config.getoption('--cloudsql_port')


@pytest.fixture
def cloudsql_username(request):
    return request.config.getoption('--cloudsql_username')


@pytest.fixture
def forseti_server_bucket_name(request):
    return request.config.getoption('--forseti_server_bucket_name')


@pytest.fixture
def forseti_server_config_path(request):
    return request.config.getoption('--forseti_server_config_path')


@pytest.fixture
def forseti_server_vm_name(request):
    return request.config.getoption('--forseti_server_vm_name')


@pytest.fixture
def root_resource_id(request):
    return request.config.getoption('--root_resource_id')


@pytest.fixture
def test_id():
    return str(int(time.time()))
