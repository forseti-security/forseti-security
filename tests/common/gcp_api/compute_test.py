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

"""Tests the Compute client."""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import compute
from tests.common.gcp_api.test_data import fake_firewall_rules


class ComputeTest(ForsetiTestCase):
    """Test the Compute client."""

    @mock.patch('google.cloud.security.common.gcp_api._base_client.discovery')
    @mock.patch('google.cloud.security.common.gcp_api._base_client.GoogleCredentials')
    def setUp(self, mock_google_credential, mock_discovery):
        """Set up."""
        fake_global_configs = {'max_compute_api_calls_per_second': 20}
        self.client = compute.ComputeClient(
            global_configs=fake_global_configs)

    def test_get_firewall_rules(self):
        self.client.service = mock.MagicMock()
        self.client.rate_limiter = mock.MagicMock()
        self.client._build_paged_result = mock.MagicMock()
        self.client._build_paged_result.return_value = (
            fake_firewall_rules.PAGED_RESULTS)

        firewall_rules = self.client.get_firewall_rules('aaaaa')

        self.assertTrue(self.client.service.firewalls.called)
        self.assertTrue(
            mock.call().list(project='aaaaa')
            in self.client.service.firewalls.mock_calls)
        self.assertEquals(fake_firewall_rules.EXPECTED_RESULTS,
                          firewall_rules)


if __name__ == '__main__':
    unittest.main()
