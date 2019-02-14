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
from tests.common.gcp_api.test_data import fake_group_settings_responses as fake_group_settings
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import group_settings

class GroupsettingTest(unittest_utils.ForsetiTestCase):
    """Test the Pub/Sub API Client."""

    @classmethod
    @mock.patch.object(
        group_settings.api_helpers, 'get_delegated_credential',
        return_value=(mock.Mock(spec_set=credentials.Credentials)))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
        	'domain_super_admin_email': 'group_settings@foo.testing',
            'groupssettings': {'max_calls': 14, 'period': 1.0}}
        cls.group_settings_api_client = group_settings.GroupSettingsClient(fake_global_configs)
        cls.group_settings_api_client.repository._use_cached_http = True

    @mock.patch.object(
        group_settings.api_helpers, 'get_delegated_credential',
        return_value=mock.Mock(spec_set=credentials.Credentials))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        group_settings_api_client = group_settings.GroupSettingsClient(global_configs={})
        self.assertEqual(None, group_settings_api_client.repository._rate_limiter)

    def test_get_group_settings(self):
	    """Test get Pub/Sub topics."""    
	    mock_response = fake_group_settings.GET_GROUP_SETTINGS_RESPONSE
	    http_mocks.mock_http_response(mock_response)

	    results = self.group_settings_api_client.get_group_settings(
	        fake_group_settings.FAKE_EMAIL)
	    self.assertEquals(results['description'] , fake_group_settings.FAKE_DESCRIPTION)

    def test_get_group_settings_raises(self):
        """Test get Pub/Sub topics error if project does not exist."""
        http_mocks.mock_http_response(fake_group_settings.UNAUTHORIZED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.group_settings_api_client.get_group_settings(fake_group_settings.FAKE_EMAIL)

if __name__ == '__main__':
    unittest.main()
