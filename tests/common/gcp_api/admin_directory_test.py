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
from oauth2client import client
from oauth2client import service_account

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_admin_directory_responses as fake_admin
from tests.common.gcp_api.test_data import fake_key_file
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.security.common.gcp_api import admin_directory as admin
from google.cloud.security.common.gcp_api import errors as api_errors


class AdminDirectoryTest(unittest_utils.ForsetiTestCase):
    """Test the GSuite Admin Directory client."""

    @classmethod
    @mock.patch('oauth2client.crypt.Signer.from_string',
                return_value=object())
    @mock.patch.object(client.GoogleCredentials, 'get_application_default',
                       spec=True)
    def setUpClass(cls, mock_default_credential, signer_factory):
        """Set up."""
        with unittest_utils.create_temp_file(
                fake_key_file.FAKE_KEYFILE) as key_file:
            fake_global_configs = {
                'groups_service_account_key_file': key_file,
                'domain_super_admin_email': 'admin@foo.testing',
                'max_admin_api_calls_per_100_seconds': 1500}
            cls.ad_api_client = admin.AdminDirectoryClient(fake_global_configs)
            mock_default_credential.assert_not_called()

    @mock.patch.object(service_account, 'ServiceAccountCredentials')
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        global_configs = {
            'groups_service_account_key_file': 'abc.key',
            'domain_super_admin_email': 'admin@foo.testing'}
        ad_api_client = admin.AdminDirectoryClient(global_configs)
        self.assertEqual(None, ad_api_client.repository._rate_limiter)

    @mock.patch.object(admin, 'LOGGER')
    @mock.patch.object(service_account, 'ServiceAccountCredentials')
    def test_deprecated_config(self, mock_credential, mock_logger):
        global_configs = {
            'groups_service_account_key_file': 'abc.key',
            'domain_super_admin_email': 'admin@foo.testing',
            'max_admin_api_calls_per_day': 150000}
        ad_api_client = admin.AdminDirectoryClient(global_configs)
        mock_logger.error.assert_called_once()
        self.assertEqual(ad_api_client.repository._rate_limiter.period, 86400.0)

    def test_get_groups(self):
        http_mocks.mock_http_response(fake_admin.FAKE_GROUPS_LIST_RESPONSE)
        response = self.ad_api_client.get_groups()

        self.assertListEqual(fake_admin.FAKE_GROUP_NAMES,
                             [g['name'] for g in response])

    def test_get_groups_raises(self):
        http_mocks.mock_http_response(fake_admin.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ad_api_client.get_groups()

    def test_get_members(self):
        http_mocks.mock_http_response(fake_admin.FAKE_MEMBERS_LIST_RESPONSE1)
        response = self.ad_api_client.get_group_members('11111')

        self.assertEqual(3, len(response))

    def test_get_members_raises(self):
        http_mocks.mock_http_response(fake_admin.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ad_api_client.get_group_members('11111')


if __name__ == '__main__':
    unittest.main()
