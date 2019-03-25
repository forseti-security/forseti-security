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
"""Tests the Forseti Server explain service."""

import unittest

from grpc._channel import _Rendezvous

from tests.services import test_models
from tests.services.api_tests.api_tester import ModelTestRunner
from tests.services.inventory import gcp_api_mocks
from tests.services.util.db import create_test_engine
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.dao import ModelManager
from google.cloud.forseti.services.explain.service import GrpcExplainerFactory
from google.cloud.forseti.services.inventory.service import GrpcInventoryFactory
from google.cloud.forseti.services.model.service import GrpcModellerFactory


class TestServiceConfig(object):
    """ServiceConfig stub."""

    def __init__(self, inventory_config):
        self.engine = create_test_engine()
        self.model_manager = ModelManager(self.engine)
        self.inventory_config = inventory_config

    def run_in_background(self, function):
        """Stub."""
        function()
        return self

    def get_engine(self):
        """Stub."""
        return self.engine


def create_tester(inventory_config):
    """Creates a model based test runner.
    
    Args:
        inventory_config (InventoryConfig): the inventory configuration

    Returns:
        ModelTestRunner: the model test runner

    """
    return ModelTestRunner(
        test_models.COMPLEX_MODEL, TestServiceConfig(inventory_config),
        [
            GrpcExplainerFactory,
            GrpcInventoryFactory,
            GrpcModellerFactory,
        ])


class ExplainerTest(ForsetiTestCase):
    """Test based on declarative model."""

    def test_explain_is_supported(self):
        """Test explain is supported."""

        inventory_config_with_organization_root = (
            InventoryConfig(gcp_api_mocks.ORGANIZATION_ID, '', {}, '', {}))
        setup = create_tester(
            inventory_config_with_organization_root)

        def test(client):
            """Test implementation with API client."""
            expected_reply = set([
                                 'role/a',
                                 'role/b',
                                 'role/c',
                                 'role/d',
                                 'roles/owner',
                                 'roles/editor',
                                 'roles/viewer',
                                 ])
            actual_reply = set(r.role_name for r in client.explain.list_roles(''))
            self.assertEqual(expected_reply,
                             actual_reply)

        setup.run(test)

    def test_explain_is_not_supported(self):
        """Test explain is not supported."""

        inventory_config_with_folder_root = (
            InventoryConfig(gcp_api_mocks.FOLDER_ID, '', {}, '', {}))
        setup = create_tester(inventory_config_with_folder_root)

        def test(client):
            """Test implementation with API client."""
            self.assertRaisesRegexp(
                _Rendezvous,
                'FAILED_PRECONDITION',
                lambda r: list(client.explain.list_roles('')),
                '')

        setup.run(test)

if __name__ == '__main__':
    unittest.main()
