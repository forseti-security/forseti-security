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
"""Unit Tests: Explain Service for Forseti Server."""

import mock
import unittest

from google.cloud.forseti.services.explain import service
from tests.unittest_utils import ForsetiTestCase


class ServiceTest(ForsetiTestCase):
    """Test Explain service."""

    def setUp(self):
        """Setup method."""
        self.maxDiff = None
        ForsetiTestCase.setUp(self)

        mock_explainer_api = mock.MagicMock()
        self.grpc_explainer = service.GrpcExplainer(mock_explainer_api)

    def tearDown(self):
        """Tear down method."""
        ForsetiTestCase.tearDown(self)

    def test_determine_is_supported(self):
        inventory_config = self.grpc_explainer.explainer.config.inventory_config
        inventory_config.root_resource_id = 'organizations/11111'
        self.assertTrue(self.grpc_explainer._determine_is_supported())

    def test_determine_is_not_supported(self):
        inventory_config = self.grpc_explainer.explainer.config.inventory_config
        inventory_config.root_resource_id = 'folders/22222'
        self.assertFalse(self.grpc_explainer._determine_is_supported())


if __name__ == '__main__':
    unittest.main()
