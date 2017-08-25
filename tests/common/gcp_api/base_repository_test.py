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

"""Tests the base repository classes."""
import datetime
import threading
import unittest
from googleapiclient import discovery
from googleapiclient import http
import mock
import oauth2client
from oauth2client import client

from tests import unittest_utils
from google.cloud import security as forseti_security
from google.cloud.security.common.gcp_api import _base_repository as base
from google.cloud.security.common.gcp_api import _supported_apis
from google.cloud.security.common.gcp_api import errors as api_errors


# From oauth2client/tests/test_service_account.py
FAKE_KEYFILE = b"""
{
  "type": "service_account",
  "client_id": "id123",
  "client_email": "foo@bar.com",
  "private_key_id": "pkid456",
  "private_key": "s3kr3tz"
}
"""


class BaseRepositoryTest(unittest_utils.ForsetiTestCase):
    """Test the Base Repository methods."""

    def test_set_user_agent(self):
        """Verify set user agent sets the user agent correctly."""
        access_token = 'foo'
        client_id = 'some_client_id'
        client_secret = 'cOuDdkfjxxnv+'
        refresh_token = '1/0/a.df219fjls0'
        token_expiry = datetime.datetime.utcnow()
        user_agent = ''
        credentials = client.OAuth2Credentials(
            access_token, client_id, client_secret,
            refresh_token, token_expiry, oauth2client.GOOGLE_TOKEN_URI,
            user_agent, revoke_uri=oauth2client.GOOGLE_REVOKE_URI,
            scopes='foo', token_info_uri=oauth2client.GOOGLE_TOKEN_INFO_URI)

        self.assertEqual('', credentials.user_agent)

        base._set_user_agent(credentials)

        self.assertTrue(
            forseti_security.__package_name__ in credentials.user_agent)

        http_mock = http.HttpMock()
        credentials.authorize(http_mock)

        # The user-agent header is set during the request
        self.assertEqual(None, http_mock.headers)

        _ = http_mock.request('http://test.foo', 'GET')
        self.assertTrue(
            forseti_security.__package_name__ in
                http_mock.headers.get('user-agent'))

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

        api_name = _supported_apis.SUPPORTED_APIS.keys()[0]
        supported_api = _supported_apis.SUPPORTED_APIS[api_name]
        mock_credentials = mock.MagicMock()

        client = base.BaseRepositoryClient(
            api_name, credentials=mock_credentials)

        self.assertEqual((api_name, [supported_api['default_version']]),
                         (client.name, client.versions))


    @mock.patch.object(discovery, 'build', autospec=True)
    @mock.patch.object(base, 'LOGGER', autospec=True)
    def test_forseti_unsupported_valid_version_is_ok(
            self,
            mock_logger,
            mock_discovery_build):
        """Test that Forseti-supported API with unsupported valid version is ok.

        Setup:
            * Pick one of the supported APIs.
            * Pick a valid version (not officially supported by Forseti).
            * Instantiate the Base Client with the API name and version.

        Expect:
            * Unsupported version will call LOGGER.warn().
        """

        api_name = 'cloudresourcemanager'
        self.assertTrue(api_name in _supported_apis.SUPPORTED_APIS)
        provided_version = 'v1beta1'
        self.assertFalse(
            provided_version in
                _supported_apis.SUPPORTED_APIS[api_name]['supported_versions'])

        mock_credentials = mock.MagicMock()

        client = base.BaseRepositoryClient(
            api_name, credentials=mock_credentials, versions=[provided_version])

        self.assertEqual((api_name, [provided_version]),
                         (client.name, client.versions))

        mock_logger.warn.assert_called_with(
            mock.ANY, api_name, provided_version)

    @mock.patch.object(discovery, 'build', autospec=True)
    @mock.patch.object(base, 'LOGGER', autospec=True)
    def test_forseti_unsupported_api_is_ok(
            self,
            mock_logger,
            mock_discovery_build):
        """Test that unsupported API is ok.

        Setup:
            * Pick a non-supported API.
            * Pick a valid version (not officially supported by Forseti).
            * Instantiate the Base Client with the API name and version.

        Expect:
            * Unsupported API will call LOGGER.warn().
        """

        api_name = 'zoo'
        self.assertFalse(api_name in _supported_apis.SUPPORTED_APIS)
        provided_versions = ['v1', 'v2']

        mock_credentials = mock.MagicMock()

        client = base.BaseRepositoryClient(
            api_name, credentials=mock_credentials, versions=provided_versions)

        expected_repr = 'API: name=zoo, versions=[\'v1\', \'v2\']'
        self.assertEqual(expected_repr, '%s' % client)

        mock_logger.warn.assert_called_with(
            mock.ANY, api_name)

    @mock.patch.object(discovery, 'build', autospec=True)
    def test_init_repository_no_supported_version(self, mock_discovery_build):
        """Verify that _init_repository will pick a version if none provided."""
        class ZooRepository(base.GCPRepository):
            def __init__(self, **kwargs):
                super(ZooRepository, self).__init__(component='a', **kwargs)

        # Return a different mock object each time build is called.
        mock_discovery_build.side_effect = [mock.Mock(), mock.Mock()]

        mock_credentials = mock.MagicMock()
        client = base.BaseRepositoryClient(
            'zoo', credentials=mock_credentials, versions=['v2', 'v1'])

        repo = client._init_repository(ZooRepository)
        self.assertEqual(client.gcp_services['v1'], repo.gcp_service)
        self.assertNotEqual(client.gcp_services['v2'], repo.gcp_service)

    def test_multiple_threads_unique_http_objects(self):
        """Validate that each thread gets its unique http object.

        At the core of this requirement is the fact that httplib2.Http is not
        thread-safe. Therefore, it is the responsibility of the repo to maintain
        a separate http object even if multiplethreads share it.
        """

        def get_http(repo, result, i):
            result[i] = repo.http

        gcp_service_mock = mock.Mock()
        credentials_mock = mock.Mock(spec=client.Credentials)
        repo = base.GCPRepository(
            gcp_service=gcp_service_mock,
            credentials=credentials_mock,
            component='fake_component')

        http_objects = [None] * 2
        t1 = threading.Thread(target=get_http, args=(repo, http_objects, 0))
        t2 = threading.Thread(target=get_http, args=(repo, http_objects, 1))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertIsNot(http_objects[0], http_objects[1])

    @mock.patch('oauth2client.crypt.Signer.from_string',
                return_value=object())
    def test_credential_from_keyfile(self, signer_factory):
        """Validate with a valid test credential file."""

        test_delegate = 'user@forseti.testing'
        with unittest_utils.create_temp_file(FAKE_KEYFILE) as f:
            credentials = base.credential_from_keyfile(
                f, 'scope', test_delegate)
            self.assertEqual(credentials._kwargs['sub'],test_delegate)

    def test_credential_from_keyfile_raises(self):
        """Validate that an invalid credential file raises exception."""
        with unittest_utils.create_temp_file(b'{}') as f:
            with self.assertRaises(api_errors.ApiExecutionError):
                base.credential_from_keyfile(f, 'scope', 'user@forseti.testing')

if __name__ == '__main__':
    unittest.main()
