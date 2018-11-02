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

"""Tests the Service Management API client."""
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_servicemanagement_responses as fake_sm
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import servicemanagement


class ServiceManagementClientTest(unittest_utils.ForsetiTestCase):
    """Test the Service Management Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'servicemanagement': {'max_calls': 2, 'period': 1.1}}
        cls.sm_api_client = servicemanagement.ServiceManagementClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify rate limiter is None if the configuration is missing."""
        sm_api_client = servicemanagement.ServiceManagementClient(
            global_configs={})
        self.assertEqual(None, sm_api_client.repository._rate_limiter)

    def test_get_enabled_apis(self):
        """Tests that get_enabled_apis returns expected number of results."""
        mock_responses = []
        for page in fake_sm.LIST_CONSUMER_SERVICES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.sm_api_client.get_enabled_apis(
            fake_sm.FAKE_PROJECT_ID)

        self.assertEquals(fake_sm.EXPECTED_CONSUMER_SERVICES_COUNT,
                          len(return_value))

    def test_get_enabled_apis_raises(self):
        """Tests that get_enabled_apis raises exception for invalid input."""
        http_mocks.mock_http_response(fake_sm.LIST_PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.sm_api_client.get_enabled_apis(fake_sm.FAKE_PROJECT_ID)

    def test_get_produced_apis(self):
        """Tests that get_produced_apis returns expected number of results."""
        mock_responses = []
        for page in fake_sm.LIST_PRODUCER_SERVICES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.sm_api_client.get_produced_apis(
            fake_sm.FAKE_PROJECT_ID)

        self.assertEquals(fake_sm.EXPECTED_PRODUCER_SERVICES_COUNT,
                          len(return_value))

    def test_get_produced_apis_raises(self):
        """Tests that get_produced_apis raises exception for invalid input."""
        http_mocks.mock_http_response(fake_sm.LIST_PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.sm_api_client.get_produced_apis(fake_sm.FAKE_PROJECT_ID)

    def test_get_all_apis(self):
        """Tests that get_all_apis returns expected number of results."""
        mock_responses = []
        for page in fake_sm.LIST_ALL_SERVICES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.sm_api_client.get_all_apis()

        self.assertEquals(fake_sm.EXPECTED_ALL_SERVICES_COUNT,
                          len(return_value))

    def test_get_api_iam_policy(self):
        """Tests that get_api_iam_policy returns expected result."""
        http_mocks.mock_http_response(fake_sm.GET_API_IAM_POLICY_RESPONSE)

        return_value = self.sm_api_client.get_api_iam_policy(
            fake_sm.FAKE_SERVICE_NAME)

        self.assertTrue('bindings' in return_value)
        self.assertEquals(fake_sm.EXPECTED_IAM_POLICY_BINDINGS_COUNT,
                          len(return_value['bindings']))

    def test_get_api_iam_policy_raises(self):
        """Tests get_api_iam_policy for an api missing required permissions."""
        http_mocks.mock_http_response(fake_sm.IAM_PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.sm_api_client.get_api_iam_policy(fake_sm.FAKE_SERVICE_NAME)


if __name__ == '__main__':
    unittest.main()
