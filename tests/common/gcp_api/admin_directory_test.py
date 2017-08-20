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

"""Tests the AppEngine client."""

import unittest
import mock

from tests.common.gcp_api.test_data import fake_admin_directory_responses as fake_admin
from tests.common.gcp_api.test_data import http_mocks
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import admin_directory as admin
from google.cloud.security.common.gcp_api import errors as api_errors


class AdminDirectoryTest(ForsetiTestCase):
    """Test the GSuite Admin Directory client."""

    @mock.patch.object(_base_repository, 'ServiceAccountCredentials')
    def setUp(self, mock_credential):
        """Set up."""
        self.fake_global_configs = {
            'groups_service_account_key_file': 'abc.key',
            'domain_super_admin_email': 'admin@foo.testing',
            'max_admin_api_calls_per_100_seconds': 1500}
        self.ad_api_client = admin.AdminDirectoryClient(
            self.fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(admin, 'LOGGER')
    @mock.patch.object(_base_repository, 'ServiceAccountCredentials')
    def test_deprecated_config(self, mock_credential, mock_logger):
        self.fake_global_configs.pop('max_admin_api_calls_per_100_seconds')
        self.fake_global_configs['max_admin_api_calls_per_day'] = 150000
        ad_api_client = admin.AdminDirectoryClient(self.fake_global_configs)
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
