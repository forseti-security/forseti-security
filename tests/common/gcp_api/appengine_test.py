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
from oauth2client import client

from tests.common.gcp_api.test_data import fake_appengine_responses as fae
from tests.common.gcp_api.test_data import http_mocks
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import appengine as ae
from google.cloud.security.common.gcp_api import errors as api_errors


class AppEngineTest(ForsetiTestCase):
    """Test the AppEngine client."""

    @classmethod
    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'max_appengine_api_calls_per_second': 20}
        cls.ae_api_client = ae.AppEngineClient(fake_global_configs,
                                               use_rate_limiter=False)

    @mock.patch.object(client, 'GoogleCredentials')
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        ae_api_client = ae.AppEngineClient(global_configs={})
        self.assertEqual(None, ae_api_client.repository._rate_limiter)

    def test_get_app(self):
        http_mocks.mock_http_response(fae.FAKE_APP_GET_RESPONSE)
        response = self.ae_api_client.get_app(fae.FAKE_PROJECT_ID)

        self.assertEqual(fae.FAKE_APP_NAME, response.get('name'))

    def test_get_app_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.get_app(fae.FAKE_PROJECT_ID)

        self.assertEqual({}, response)

    def test_get_app_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.get_app(fae.FAKE_PROJECT_ID)


if __name__ == '__main__':
    unittest.main()
