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

"""Tests the IAM API client."""
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_iam_responses as fake_iam
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import iam


class IamTest(unittest_utils.ForsetiTestCase):
    """Test the IAM Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'iam': {'max_calls': 18, 'period': 1}}
        cls.iam_api_client = iam.IAMClient(global_configs=fake_global_configs)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        iam_api_client = iam.IAMClient(global_configs={})
        self.assertEqual(None, iam_api_client.repository._rate_limiter)

    def test_get_curated_roles(self):
        """Test get iam curated roles."""
        mock_responses = []
        for page in fake_iam.GET_ROLES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.iam_api_client.get_curated_roles()
        self.assertEquals(fake_iam.EXPECTED_ROLE_NAMES,
                          [r.get('name') for r in results])

    def test_get_curated_roles_raises(self):
        """Test get iam currated roles permission denied."""
        http_mocks.mock_http_response(fake_iam.PERMISSION_DENIED, '403')
        org_id = 'organizations/{}'.format(fake_iam.FAKE_ORG_ID)

        with self.assertRaises(api_errors.ApiExecutionError):
            self.iam_api_client.get_curated_roles(org_id)

    def test_get_organization_roles(self):
        """Test get iam organizations custom roles."""
        http_mocks.mock_http_response(fake_iam.GET_ORGANIZATION_ROLES)

        results = self.iam_api_client.get_organization_roles(
            fake_iam.FAKE_ORG_ID)

        self.assertEquals(fake_iam.EXPECTED_ORGANIZATION_ROLE_NAMES,
                          [r.get('name') for r in results])

    def test_get_organization_roles_raises(self):
        """Test get iam organizations custom roles permission denied."""
        http_mocks.mock_http_response(fake_iam.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.iam_api_client.get_organization_roles(fake_iam.FAKE_ORG_ID)

    def test_get_project_roles(self):
        """Test get iam projects custom roles."""
        http_mocks.mock_http_response(fake_iam.GET_PROJECT_ROLES)

        results = self.iam_api_client.get_project_roles(
            fake_iam.FAKE_PROJECT_ID)

        self.assertEquals(fake_iam.EXPECTED_PROJECT_ROLE_NAMES,
                          [r.get('name') for r in results])

    def test_get_project_roles_raises(self):
        """Test get iam projects custom roles permission denied."""
        http_mocks.mock_http_response(fake_iam.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.iam_api_client.get_project_roles(fake_iam.FAKE_PROJECT_ID)

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

    def test_get_service_account_keys_key_type(self):
        """Test get iam project service accounts."""
        http_mocks.mock_http_response(
            fake_iam.GET_PROJECTS_SERVICEACCOUNTS_KEYS)

        for key_type in self.iam_api_client.KEY_TYPES:
            result = self.iam_api_client.get_service_account_keys(
                fake_iam.FAKE_SERVICEACCOUNT_NAME, key_type=key_type)

            self.assertEquals(fake_iam.EXPECTED_SERVICE_ACCOUNT_KEYS, result)

    def test_get_service_account_keys_invalid_key_type(self):
        """Test get iam project service accounts with invalid key_type."""
        http_mocks.mock_http_response(
            fake_iam.GET_PROJECTS_SERVICEACCOUNTS_KEYS)

        with self.assertRaises(ValueError):
            self.iam_api_client.get_service_account_keys(
                fake_iam.FAKE_SERVICEACCOUNT_NAME, key_type='Other')

    def test_get_service_account_keys_raises(self):
        """Test get iam project service accounts not found."""
        http_mocks.mock_http_response(fake_iam.SERVICE_ACCOUNT_NOT_FOUND, '404')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.iam_api_client.get_service_account_keys(
                fake_iam.FAKE_SERVICEACCOUNT_NAME)

    def test_get_service_account_iam_policy(self):
        """Test get iam project service accounts."""
        http_mocks.mock_http_response(
            fake_iam.GET_PROJECT_SERVICEACCOUNT_IAM_POLICY)

        result = self.iam_api_client.get_service_account_iam_policy(
            fake_iam.FAKE_SERVICEACCOUNT_NAME)

        self.assertTrue('bindings' in result)

    def test_get_service_account_iam_policy_raises(self):
        """Test get iam project service accounts not found."""
        http_mocks.mock_http_response(fake_iam.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.iam_api_client.get_service_account_iam_policy(
                fake_iam.FAKE_SERVICEACCOUNT_NAME)


if __name__ == '__main__':
    unittest.main()
