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

"""Tests the AppEngine client."""
import unittest
from googleapiclient import errors
import mock
import httplib2
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_appengine_responses as fae
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import appengine as ae
from google.cloud.forseti.common.gcp_api import errors as api_errors


class AppEngineTest(unittest_utils.ForsetiTestCase):
    """Test the AppEngine client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'appengine': {'max_calls': 18, 'period': 1}}
        cls.ae_api_client = ae.AppEngineClient(fake_global_configs,
                                               use_rate_limiter=False)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        ae_api_client = ae.AppEngineClient(global_configs={})
        self.assertEqual(None, ae_api_client.repository._rate_limiter)

    def test_is_status_not_found_404(self):
        response = httplib2.Response({
            'status': '404',
            'content-type': 'application/json'})
        response.reason = 'Not Found'
        error = errors.HttpError(response, fae.APP_NOT_FOUND, uri='')
        self.assertTrue(ae._is_status_not_found(error))

    def test_is_status_not_found_403(self):
        response = httplib2.Response({
            'status': '403',
            'content-type': 'application/json'})
        response.reason = 'Permission Denied'
        error = errors.HttpError(response, fae.PERMISSION_DENIED, uri='')
        self.assertFalse(ae._is_status_not_found(error))

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

    def test_get_service(self):
        http_mocks.mock_http_response(fae.GET_SERVICE_RESPONSE)
        response = self.ae_api_client.get_service(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID)

        self.assertEqual(fae.EXPECTED_SERVICE_NAMES[0], response.get('name'))

    def test_get_service_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.get_service(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID)

        self.assertEqual({}, response)

    def test_get_service_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.get_service(
                fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID)

    def test_list_services(self):
        http_mocks.mock_http_response(fae.LIST_SERVICES_RESPONSE)
        response = self.ae_api_client.list_services(fae.FAKE_PROJECT_ID)

        self.assertEquals(fae.EXPECTED_SERVICE_NAMES,
                          [r.get('name') for r in response])

    def test_list_services_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.list_services(fae.FAKE_PROJECT_ID)

        self.assertEqual([], response)

    def test_list_services_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.list_services(fae.FAKE_PROJECT_ID)

    def test_get_version(self):
        http_mocks.mock_http_response(fae.GET_VERSION_RESPONSE)
        response = self.ae_api_client.get_version(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID)

        self.assertEqual(fae.EXPECTED_VERSION_NAMES[0], response.get('name'))

    def test_get_version_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.get_version(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID)

        self.assertEqual({}, response)

    def test_get_version_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.get_version(
                fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID)

    def test_list_versions(self):
        mock_responses = []
        for page in fae.LIST_VERSIONS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        response = self.ae_api_client.list_versions(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID)

        self.assertEquals(fae.EXPECTED_VERSION_NAMES,
                          [r.get('name') for r in response])

    def test_list_versions_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.list_versions(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID)

        self.assertEqual([], response)

    def test_list_versions_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.list_versions(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID)

    def test_get_instance(self):
        http_mocks.mock_http_response(fae.GET_INSTANCE_RESPONSE)
        response = self.ae_api_client.get_instance(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID,
            fae.FAKE_INSTANCE_ID)

        self.assertEqual(fae.EXPECTED_INSTANCE_NAMES[0], response.get('name'))

    def test_get_instance_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.get_instance(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID,
            fae.FAKE_INSTANCE_ID)

        self.assertEqual({}, response)

    def test_get_instance_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.get_instance(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID,
            fae.FAKE_INSTANCE_ID)

    def test_list_instances(self):
        http_mocks.mock_http_response(fae.LIST_INSTANCES_RESPONSE)

        response = self.ae_api_client.list_instances(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID)

        self.assertEquals(fae.EXPECTED_INSTANCE_NAMES,
                          [r.get('name') for r in response])

    def test_list_instances_not_found(self):
        http_mocks.mock_http_response(fae.APP_NOT_FOUND, '404')
        response = self.ae_api_client.list_instances(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID)

        self.assertEqual([], response)

    def test_list_instances_raises(self):
        http_mocks.mock_http_response(fae.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.ae_api_client.list_instances(
            fae.FAKE_PROJECT_ID, fae.FAKE_SERVICE_ID, fae.FAKE_VERSION_ID)


if __name__ == '__main__':
    unittest.main()
