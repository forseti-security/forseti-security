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

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import appengine

class AppEngineTest(ForsetiTestCase):
    """Test the AppEngine client."""

    @mock.patch('google.cloud.security.common.gcp_api._base_client.discovery')
    @mock.patch('google.cloud.security.common.gcp_api._base_client.GoogleCredentials')
    def setUp(self, mock_google_credential, mock_discovery):
        """Set up."""

        mock_discovery.__name__ = 'discovery'
        fake_global_configs = {
            'max_appengine_api_calls_per_second': 20}
        self.client = appengine.AppEngineClient(fake_global_configs)

    def test_get_app(self):
        self.client.service = mock.MagicMock()
        apps = mock.MagicMock()
        apps.get = mock.MagicMock()
        self.client.service.apps = mock.MagicMock(return_value=apps)
        self.client.rate_limiter = mock.MagicMock()
        self.client._execute = mock.MagicMock()

        app = self.client.get_app('aaaaa')

        self.assertTrue(self.client.service.apps.called)
        apps.get.assert_called_with(appsId='aaaaa')


if __name__ == '__main__':
    unittest.main()
