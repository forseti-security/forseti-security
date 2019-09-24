# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Tests the Service Usage API client."""
import unittest
import unittest.mock as mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_serviceusage_responses as fake_su
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import serviceusage

class ServiceUsageClientTest(unittest_utils.ForsetiTestCase):
    """Test the Service Usage Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'serviceusage': {'max_calls': 4, 'period': 1.1}}
        cls.su_api_client = serviceusage.ServiceUsageClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify rate limiter is None if the configuration is missing."""
        su_api_client = serviceusage.ServiceUsageClient(global_configs={})
        self.assertEqual(None, su_api_client.repository._rate_limiter)

    def test_get_enabled_apis(self):
        """Tests that get_enabled_apis returns expected number of results."""
        mock_responses = []
        for page in fake_su.LIST_SERVICES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.su_api_client.get_enabled_apis(
            fake_su.FAKE_PROJECT_ID)

        self.assertEqual(fake_su.EXPECTED_SERVICES_COUNT, len(return_value))

    def test_get_enabled_apis_raises(self):
        """Tests that get_enabled_apis raises exception for invalid input."""
        http_mocks.mock_http_response(fake_su.LIST_PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.su_api_client.get_enabled_apis(fake_su.FAKE_PROJECT_ID)

if __name__ == '__main__':
    unittest.main()
