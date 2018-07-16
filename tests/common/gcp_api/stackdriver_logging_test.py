# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Tests the Stackdriver Logging API client."""
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_stackdriver_logging_responses as fake_sd_logging
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import stackdriver_logging


class StackdriverLoggingTest(unittest_utils.ForsetiTestCase):
    """Test the Stackdriver Logging Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'logging': {'max_calls': 18, 'period': 1}}
        cls.logging_api_client = stackdriver_logging.StackdriverLoggingClient(
            global_configs=fake_global_configs)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        logging_api_client = stackdriver_logging.StackdriverLoggingClient(
            global_configs={})
        self.assertEqual(None, logging_api_client.repository._rate_limiter)

    def test_get_organization_sinks(self):
        """Test get logging organization sinks."""
        mock_responses = []
        for page in fake_sd_logging.GET_SINKS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.logging_api_client.get_organization_sinks(
            fake_sd_logging.FAKE_ORG_ID)
        self.assertEquals(fake_sd_logging.EXPECTED_SINK_NAMES,
                          [r.get('name') for r in results])

    def test_get_organization_sinks_raises(self):
        """Test get logging organization sinks permission denied."""
        http_mocks.mock_http_response(fake_sd_logging.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.logging_api_client.get_organization_sinks(
                fake_sd_logging.FAKE_ORG_ID)

    def test_get_folder_sinks(self):
        """Test get logging folder sinks."""
        mock_responses = []
        for page in fake_sd_logging.GET_SINKS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.logging_api_client.get_folder_sinks(
            fake_sd_logging.FAKE_FOLDER_ID)
        self.assertEquals(fake_sd_logging.EXPECTED_SINK_NAMES,
                          [r.get('name') for r in results])

    def test_get_folder_sinks_raises(self):
        """Test get logging folder sinks not found."""
        http_mocks.mock_http_response(fake_sd_logging.NOT_FOUND, '404')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.logging_api_client.get_folder_sinks(
                fake_sd_logging.FAKE_ORG_ID)

    def test_get_billing_account_sinks(self):
        """Test get logging billing account sinks."""
        mock_responses = []
        for page in fake_sd_logging.GET_SINKS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.logging_api_client.get_billing_account_sinks(
            fake_sd_logging.FAKE_BILLING_ACCOUNT_ID)
        self.assertEquals(fake_sd_logging.EXPECTED_SINK_NAMES,
                          [r.get('name') for r in results])

    def test_get_billing_account_sinks_raises(self):
        """Test get logging billing account sinks permission denied."""
        http_mocks.mock_http_response(fake_sd_logging.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.logging_api_client.get_billing_account_sinks(
                fake_sd_logging.FAKE_BILLING_ACCOUNT_ID)

    def test_get_project_sinks(self):
        """Test get logging project sinks."""
        mock_responses = []
        for page in fake_sd_logging.GET_SINKS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.logging_api_client.get_project_sinks(
            fake_sd_logging.FAKE_PROJECT_ID)
        self.assertEquals(fake_sd_logging.EXPECTED_SINK_NAMES,
                          [r.get('name') for r in results])

    def test_get_project_sinks_raises(self):
        """Test get logging project sinks permission denied."""
        http_mocks.mock_http_response(fake_sd_logging.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.logging_api_client.get_project_sinks(
                fake_sd_logging.FAKE_PROJECT_ID)


if __name__ == '__main__':
    unittest.main()
