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

"""Tests the CloudSQL API client."""
import unittest
import mock
from oauth2client import client

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_servicemanagement_responses as fake_sm
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import servicemanagement


class ServiceManagementClientTest(unittest_utils.ForsetiTestCase):
    """Test the Service Management Client."""

    @classmethod
    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'max_servicemanagement_api_calls_per_100_seconds': 200}
        cls.sm_api_client = servicemanagement.ServiceManagementClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(client, 'GoogleCredentials')
    def test_no_quota(self, mock_google_credential):
        """Verify rate limiter is used even if the configuration is missing."""
        sm_api_client = servicemanagement.ServiceManagementClient(
            global_configs={})
        self.assertTrue(sm_api_client.repository._rate_limiter)

    def test_get_enabled_apis(self):
        """Test that get_enabled_apis returns correctly."""
        mock_responses = []
        for page in fake_sm.LIST_CONSUMER_SERVICES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.sm_api_client.get_enabled_apis(
            fake_sm.FAKE_PROJECT_ID)

        self.assertEquals(fake_sm.EXPECTED_SERVICES_COUNT, len(return_value))

    def test_get_enabled_apis_raises(self):
        """Test get cloudsql instances."""
        http_mocks.mock_http_response(fake_sm.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.sm_api_client.get_enabled_apis(fake_sm.FAKE_PROJECT_ID)


if __name__ == '__main__':
    unittest.main()
