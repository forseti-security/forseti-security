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

"""Tests the base API client."""

from googleapiclient.errors import HttpError
from httplib2 import HttpLib2Error
import mock

from apiclient import discovery
import unittest
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import _supported_apis


class BaseClientTest(unittest.TestCase):

    def setUp(self):
        self.supported_apis = _supported_apis.SUPPORTED_APIS

    @mock.patch.object(discovery, 'build', autospec=True)
    def test_forseti_supported_api_is_ok(
            self,
            mock_discovery_build):
        """Test that Forseti-supported API in BaseClient.__init__() works.

        Setup:
            * Pick one of the supported APIs.
            * Instantiate the Base Client with just the API name.

        Expect:
            * The resulting API client service has the same API name and
              version as the supported API.
        """

        api_name = self.supported_apis.keys()[0]
        supported_api = self.supported_apis[api_name]
        mock_credentials = mock.MagicMock()

        client = _base_client.BaseClient(credentials=mock_credentials,
                                         api_name=api_name)

        self.assertEqual((api_name, supported_api['version']),
                         (client.name, client.version))

    @mock.patch.object(discovery, 'build', autospec=True)
    def test_forseti_unsupported_valid_version_is_ok(
            self,
            mock_discovery_build):
        """Test that Forseti-supported API with unsupported valid version is ok.

        Setup:
            * Pick one of the supported APIs.
            * Pick a valid version (not officially supported by Forseti).
            * Instantiate the Base Client with the API name and version.

        Expect:
            * The resulting API client service has the same API name and
              version as the supported API.
            * Unsupported version will call LOGGER.warn().
        """

        api_name = 'cloudresourcemanager'
        provided_version = 'v1beta1'
        mock_credentials = mock.MagicMock()
        _base_client.LOGGER = mock.MagicMock()

        client = _base_client.BaseClient(credentials=mock_credentials,
                                         api_name=api_name,
                                         version=provided_version)

        self.assertEqual((api_name, provided_version),
                         (client.name, client.version))

        self.assertEqual(1, _base_client.LOGGER.warn.call_count)


if __name__ == '__main__':
    unittest.main()
