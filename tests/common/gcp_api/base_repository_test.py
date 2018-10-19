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

"""Tests the base repository classes."""
import datetime
import threading
import unittest
from googleapiclient import discovery
from googleapiclient import http
import mock
import google.auth
from google.oauth2 import credentials
from google.oauth2 import service_account

from tests import unittest_utils
from google.cloud import forseti as forseti_security
from google.cloud.forseti.common.gcp_api import _base_repository as base
from google.cloud.forseti.common.gcp_api import _supported_apis


class BaseRepositoryTest(unittest_utils.ForsetiTestCase):
    """Test the Base Repository methods."""

    def get_test_credential(self):
        access_token = 'foo'
        client_id = 'some_client_id'
        client_secret = 'cOuDdkfjxxnv+'
        refresh_token = '1/0/a.df219fjls0'
        token_uri = 'https://example.com/oauth2/token'
        token_expiry = datetime.datetime.utcnow()
        user_agent = ''
        creds = credentials.Credentials(
            access_token, refresh_token=refresh_token,
            token_uri=token_uri, client_id=client_id,
            client_secret=client_secret, scopes=['foo'])
        creds.expiry = token_expiry
        return creds

    @mock.patch('google.auth.crypt.rsa.RSASigner.from_string',
                return_value=object())
    def get_test_service_account(self, mock_signer):
        keyfile_dict = {
            'type': 'service_account',
            'client_email': 'test@service.account',
            'private_key': '12345',
            'private_key_id': '12345',
            'client_id': '123',
            'token_uri': 'https://example.com/oauth2/token'}
        creds = (
            service_account.Credentials.from_service_account_info(
                keyfile_dict))
        return creds

    def test_build_http(self):
        """Verify set user agent sets the user agent correctly."""
        http_mock = http.HttpMock()
        h = base.http_helpers.build_http(http=http_mock)

        _ = h.request('http://test.foo', 'GET')
        self.assertTrue(
            forseti_security.__package_name__ in
                h.headers.get('user-agent'))

    def test_build_http_multiple(self):
        """Verify set user agent sets the user agent only once."""
        http_mock = http.HttpMock()
        h = base.http_helpers.build_http(http=http_mock)
        for _ in xrange(5):
            h = base.http_helpers.build_http(http=h)

        _ = h.request('http://test.foo', 'GET')
        user_agent = h.headers.get('user-agent')
        forseti_agent_count = user_agent.count(
            forseti_security.__package_name__)
        self.assertEqual(1, forseti_agent_count)

    def test_set_scopes(self):
        creds = self.get_test_service_account()
        self.assertTrue(creds.requires_scopes)
        scoped_creds = base.with_scopes_if_required(
            creds, list(base.CLOUD_SCOPES))
        self.assertFalse(scoped_creds.requires_scopes)

    @mock.patch.object(discovery, 'build', autospec=True)
    def test_forseti_supported_api_is_ok(
            self,
            mock_discovery_build):
        """Test that Forseti-supported API in BaseClient.__init__() works.

        Args:
            mock_discovery_build (Mock): Mock object.

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

        repo_client = base.BaseRepositoryClient(
            api_name, credentials=mock_credentials)

        self.assertEqual((api_name, [supported_api['default_version']]),
                         (repo_client.name, repo_client.versions))


    @mock.patch.object(discovery, 'build', autospec=True)
    @mock.patch.object(base, 'LOGGER', autospec=True)
    def test_forseti_unsupported_valid_version_is_ok(
            self,
            mock_logger,
            mock_discovery_build):
        """Test that Forseti-supported API with unsupported valid version is ok.

        Args:
            mock_logger (Mock): Mock objects.
            mock_discovery_build (Mock): Mock object.

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

        repo_client = base.BaseRepositoryClient(
            api_name, credentials=mock_credentials, versions=[provided_version])

        self.assertEqual((api_name, [provided_version]),
                         (repo_client.name, repo_client.versions))

        mock_logger.warn.assert_called_with(
            mock.ANY, api_name, provided_version)

    @mock.patch.object(discovery, 'build', autospec=True)
    @mock.patch.object(base, 'LOGGER', autospec=True)
    def test_forseti_unsupported_api_is_ok(
            self,
            mock_logger,
            mock_discovery_build):
        """Test that unsupported API is ok.

        Args:
            mock_logger (Mock): Mock objects.
            mock_discovery_build (Mock): Mock object.

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

        repo_client = base.BaseRepositoryClient(
            api_name, credentials=mock_credentials, versions=provided_versions)

        expected_repr = 'API: name=zoo, versions=[\'v1\', \'v2\']'
        self.assertEqual(expected_repr, '%s' % repo_client)

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
        repo_client = base.BaseRepositoryClient(
            'zoo', credentials=mock_credentials, versions=['v2', 'v1'])

        repo = repo_client._init_repository(ZooRepository)
        self.assertEqual(repo_client.gcp_services['v1'], repo.gcp_service)
        self.assertNotEqual(repo_client.gcp_services['v2'], repo.gcp_service)

    def test_multiple_threads_unique_http_objects(self):
        """Validate that each thread gets its unique http object.

        At the core of this requirement is the fact that httplib2.Http is not
        thread-safe. Therefore, it is the responsibility of the repo to maintain
        a separate http object even if multiplethreads share it.
        """

        def get_http(repo, result, i):
            result[i] = repo.http

        gcp_service_mock = mock.Mock()
        credentials_mock = mock.Mock(spec=credentials.Credentials)
        repo = base.GCPRepository(
            gcp_service=gcp_service_mock,
            credentials=credentials_mock,
            component='fake_component',
            use_cached_http=True)

        http_objects = [None] * 2
        t1 = threading.Thread(target=get_http, args=(repo, http_objects, 0))
        t2 = threading.Thread(target=get_http, args=(repo, http_objects, 1))

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertNotEqual(http_objects[0], http_objects[1])

    @mock.patch('google.auth.crypt.rsa.RSASigner.from_string',
                return_value=object())
    def test_no_cached_http_gets_different_http_objects(self, signer_factory):
        """Validate that each unique credential gets a unique http object.

        At the core of this requirement is the fact that some API's require
        distinctly scoped credentials, whereas the authenticated http object
        is cached for all clients in the same thread.
        """
        http_objects = [None] * 2
        for i in range(2):
            gcp_service_mock = mock.Mock()
            fake_credentials = self.get_test_credential()
            repo = base.GCPRepository(
                gcp_service=gcp_service_mock,
                credentials=fake_credentials,
                component='fake_component{}'.format(i),
                use_cached_http=False)
            http_objects[i] = repo.http

        self.assertNotEqual(http_objects[0], http_objects[1])

    @mock.patch('google.auth.crypt.rsa.RSASigner.from_string',
                return_value=object())
    def test_use_cached_http_gets_same_http_objects(self, signer_factory):
        """Different clients with the same credential get the same http object.

        This verifies that a new http object is not created when two
        repository clients use the same credentials object.
        """
        fake_credentials = self.get_test_credential()

        http_objects = [None] * 2
        for i in range(2):
            gcp_service_mock = mock.Mock()
            repo = base.GCPRepository(
                gcp_service=gcp_service_mock,
                credentials=fake_credentials,
                component='fake_component{}'.format(i),
                use_cached_http=True)
            http_objects[i] = repo.http

        self.assertEqual(http_objects[0], http_objects[1])


if __name__ == '__main__':
    unittest.main()
