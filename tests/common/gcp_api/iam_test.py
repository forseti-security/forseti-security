# Copyright 2017 Google Inc.
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

"""Tests the IAM API client."""

import unittest
import mock

from tests.common.gcp_api.test_data import fake_iam_responses as fake_iam
from tests.common.gcp_api.test_data import http_mocks
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import iam


# pylint: disable=bad-indentation
class IamTest(ForsetiTestCase):
    """Test the IAM Client."""

    @mock.patch.object(_base_repository, 'GoogleCredentials')
    def setUp(self, mock_google_credential):
        """Set up."""
        fake_global_configs = {'max_iam_api_calls_per_second': 10000}
        self.iam_api_client = iam.IAMClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    def test_get_service_accounts(self):
        """Test get iam project service accounts."""
        http_mocks.mock_http_response(fake_iam.GET_PROJECTS_SERVICEACCOUNTS)

        result = self.iam_api_client.get_service_accounts(
            fake_iam.FAKE_PROJECT_ID)

        self.assertEquals(fake_iam.EXPECTED_SERVICE_ACCOUNTS, result)

    def test_get_service_accounts_raises(self):
        """Test get iam project service accounts permission denied."""
        http_mocks.mock_http_response(fake_iam.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.iam_api_client.get_service_accounts(fake_iam.FAKE_PROJECT_ID)

    def test_get_service_account_keys(self):
        """Test get iam project service accounts."""
        http_mocks.mock_http_response(
            fake_iam.GET_PROJECTS_SERVICEACCOUNTS_KEYS)

        result = self.iam_api_client.get_service_account_keys(
            fake_iam.FAKE_SERVICEACCOUNT_NAME)

        self.assertEquals(fake_iam.EXPECTED_SERVICE_ACCOUNT_KEYS, result)

    def test_get_service_account_keys_raises(self):
        """Test get iam project service accounts not found."""
        http_mocks.mock_http_response(fake_iam.SERVICE_ACCOUNT_NOT_FOUND, '404')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.iam_api_client.get_service_account_keys(
                 fake_iam.FAKE_SERVICEACCOUNT_NAME)


if __name__ == '__main__':
    unittest.main()
