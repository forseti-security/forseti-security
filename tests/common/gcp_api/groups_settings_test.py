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
from tests.common.gcp_api.test_data import fake_groups_settings_responses as fake_groups_settings
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import groups_settings

class GroupsSettingsTest(unittest_utils.ForsetiTestCase):
    """Test the GroupsSettings API Client."""

    @classmethod
    @mock.patch.object(
        groups_settings.api_helpers, 'get_delegated_credential',
        return_value=(mock.Mock(spec_set=credentials.Credentials)))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
        	'domain_super_admin_email': 'groups_settings@foo.testing',
            'groupssettings': {'max_calls': 14, 'period': 1.0}}
        cls.groups_settings_api_client = groups_settings.GroupsSettingsClient(fake_global_configs)
        cls.groups_settings_api_client.repository._use_cached_http = True

    @mock.patch.object(
        groups_settings.api_helpers, 'get_delegated_credential',
        return_value=mock.Mock(spec_set=credentials.Credentials))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        groups_settings_api_client = groups_settings.GroupsSettingsClient(global_configs={})
        self.assertEqual(None, groups_settings_api_client.repository._rate_limiter)

    def test_get_groups_settings(self):
	    """Test get groups settings."""    
	    mock_response = fake_groups_settings.GET_GROUPS_SETTINGS_RESPONSE
	    http_mocks.mock_http_response(mock_response)

	    results = self.groups_settings_api_client.get_groups_settings(
	        fake_groups_settings.FAKE_EMAIL)
	    self.assertEquals(results['description'] , fake_groups_settings.FAKE_DESCRIPTION)

    def test_get_groups_settings_raises(self):
        """Test get groups settings error if group does not exist."""
        http_mocks.mock_http_response(fake_groups_settings.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.groups_settings_api_client.get_groups_settings(fake_groups_settings.FAKE_EMAIL)

if __name__ == '__main__':
    unittest.main()
