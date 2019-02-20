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

"""Tests the Admin Directory  API client."""
import unittest
import mock
import google.auth
from google.auth import exceptions
from google.oauth2 import credentials
from google.oauth2 import service_account

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_admin_directory_responses as fake_admin
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import admin_directory as admin
from google.cloud.forseti.common.gcp_api import errors as api_errors


class AdminDirectoryTest(unittest_utils.ForsetiTestCase):
    """Test the GSuite Admin Directory client."""

    @classmethod
    @mock.patch.object(
        admin.api_helpers, 'get_delegated_credential',
        return_value=mock.Mock(spec_set=credentials.Credentials))
    def setUpClass(cls, mock_admin_credential):
        """Set up."""
        fake_global_configs = {
            'domain_super_admin_email': 'admin@foo.testing',
            'admin': {'max_calls': 14, 'period': 1}}
        cls.ad_api_client = admin.AdminDirectoryClient(fake_global_configs)

        # Override _use_cached_http so we can use mock http response objects
        cls.ad_api_client.repository._use_cached_http = True

    @mock.patch.object(
        admin.api_helpers, 'get_delegated_credential',
        return_value=mock.Mock(spec_set=credentials.Credentials))
    def test_no_quota(self, mock_admin_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        global_configs = {
            'groups_service_account_key_file': 'abc.key',
            'domain_super_admin_email': 'admin@foo.testing'}
        ad_api_client = admin.AdminDirectoryClient(global_configs)
        self.assertEqual(None, ad_api_client.repository._rate_limiter)

    def test_get_groups(self):
        http_mocks.mock_http_response(fake_admin.FAKE_GROUPS_LIST_RESPONSE)
        response = self.ad_api_client.get_groups()

        self.assertListEqual(fake_admin.FAKE_GROUP_NAMES,
                             [g['name'] for g in response])

    def test_get_groups_raises(self):
        http_mocks.mock_http_response(fake_admin.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ad_api_client.get_groups()

    @mock.patch.object(admin, 'LOGGER')
    def test_get_groups_raises_http_access_token_refresh_error(
            self, mock_logger):
        with mock.patch.object(
                self.ad_api_client.repository.groups, 'list') as mock_list:
            mock_list.side_effect = exceptions.RefreshError

            with self.assertRaises(exceptions.RefreshError):
                self.ad_api_client.get_groups()

        mock_logger.exception.assert_called_with(admin.GSUITE_AUTH_FAILURE_MESSAGE)

    def test_get_members(self):
        http_mocks.mock_http_response(fake_admin.FAKE_MEMBERS_LIST_RESPONSE1)
        response = self.ad_api_client.get_group_members('11111')

        self.assertEqual(3, len(response))

    def test_get_members_raises(self):
        http_mocks.mock_http_response(fake_admin.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ad_api_client.get_group_members('11111')

    def test_get_users(self):
        http_mocks.mock_http_response(fake_admin.FAKE_USERS_LIST_RESPONSE)
        response = self.ad_api_client.get_users()

        self.assertEqual(1, len(response))

    def test_get_users_raises(self):
        http_mocks.mock_http_response(fake_admin.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ad_api_client.get_users()

    @mock.patch.object(admin, 'LOGGER')
    def test_get_users_raises_http_access_token_refresh_error(
            self, mock_logger):
        with mock.patch.object(
                self.ad_api_client.repository.users, 'list') as mock_list:
            mock_list.side_effect = exceptions.RefreshError

            with self.assertRaises(exceptions.RefreshError):
                self.ad_api_client.get_users()

        mock_logger.exception.assert_called_with(admin.GSUITE_AUTH_FAILURE_MESSAGE)

if __name__ == '__main__':
    unittest.main()
