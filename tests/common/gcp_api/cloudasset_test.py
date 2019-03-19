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

"""Tests the CloudAsset API client."""
import json
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_cloudasset_responses as fake_cloudasset
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import cloudasset
from google.cloud.forseti.common.gcp_api import errors as api_errors


class CloudAssetTest(unittest_utils.ForsetiTestCase):
    """Test the CloudAssetClient."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'cloudasset': {'max_calls': 1, 'period': 1.0}}
        cls.asset_api_client = cloudasset.CloudAssetClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        asset_api_client = cloudasset.CloudAssetClient(global_configs={})
        self.assertEqual(None, asset_api_client.repository._rate_limiter)

    def test_export_assets_folder(self):
        """Test export_assets for a folder."""
        http_mocks.mock_http_response(
            fake_cloudasset.EXPORT_ASSETS_FOLDER_RESOURCES_OPERATION)

        result = self.asset_api_client.export_assets(
            fake_cloudasset.FOLDER, fake_cloudasset.DESTINATION,
            content_type='RESOURCE',
            asset_types=fake_cloudasset.ASSET_TYPES)

        self.assertEquals(json.loads(
            fake_cloudasset.EXPORT_ASSETS_FOLDER_RESOURCES_OPERATION), result)

    def test_export_assets_project(self):
        """Test export_assets for a project."""
        http_mocks.mock_http_response(
            fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION)

        result = self.asset_api_client.export_assets(
            fake_cloudasset.PROJECT, fake_cloudasset.DESTINATION,
            content_type='RESOURCE')

        self.assertEquals(json.loads(
            fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION), result)

    def test_export_assets_organization(self):
        """Test export_assets for an organization."""
        http_mocks.mock_http_response(
            fake_cloudasset.EXPORT_ASSETS_ORGANIZATION_RESOURCES_OPERATION)

        result = self.asset_api_client.export_assets(
            fake_cloudasset.ORGANIZATION, fake_cloudasset.DESTINATION,
            content_type='RESOURCE',
            asset_types=['cloudresourcemanager.googleapis.com/Project'])

        self.assertEquals(
            json.loads(
                fake_cloudasset.EXPORT_ASSETS_ORGANIZATION_RESOURCES_OPERATION),
            result)

    def test_export_assets_folder_blocking(self):
        """Test export_assets for a folder in blocking mode."""
        mock_responses = [
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_FOLDER_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_FOLDER_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_FOLDER_RESOURCES_DONE)]
        http_mocks.mock_http_response_sequence(mock_responses)

        with mock.patch.object(self.asset_api_client,
                               'OPERATION_DELAY_IN_SEC', 0.1):
            result = self.asset_api_client.export_assets(
                fake_cloudasset.FOLDER, fake_cloudasset.DESTINATION,
                content_type='RESOURCE',
                asset_types=fake_cloudasset.ASSET_TYPES,
                blocking=True)

        self.assertEquals(json.loads(
            fake_cloudasset.EXPORT_ASSETS_FOLDER_RESOURCES_DONE), result)

    def test_export_assets_project_blocking(self):
        """Test export_assets for a project in blocking mode."""
        mock_responses = [
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_DONE)]
        http_mocks.mock_http_response_sequence(mock_responses)

        with mock.patch.object(self.asset_api_client,
                               'OPERATION_DELAY_IN_SEC', 0.1):
            result = self.asset_api_client.export_assets(
                fake_cloudasset.PROJECT, fake_cloudasset.DESTINATION,
                content_type='RESOURCE',
                asset_types=['cloudresourcemanager.googleapis.com/Project'],
                blocking=True)

        self.assertEquals(json.loads(
            fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_DONE), result)

    def test_export_assets_organization_blocking(self):
        """Test export_assets for an organization in blocking mode."""
        mock_responses = [
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_ORGANIZATION_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_ORGANIZATION_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_ORGANIZATION_RESOURCES_DONE)]
        http_mocks.mock_http_response_sequence(mock_responses)

        with mock.patch.object(self.asset_api_client,
                               'OPERATION_DELAY_IN_SEC', 0.1):
            result = self.asset_api_client.export_assets(
                fake_cloudasset.ORGANIZATION, fake_cloudasset.DESTINATION,
                content_type='RESOURCE', blocking=True)

        self.assertEquals(json.loads(
            fake_cloudasset.EXPORT_ASSETS_ORGANIZATION_RESOURCES_DONE), result)

    def test_export_assets_project_blocking_timeout(self):
        """Test export_assets for a project in blocking mode with a timeout."""
        mock_responses = [
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_OPERATION),
            ({'status': '200'},
             fake_cloudasset.EXPORT_ASSETS_PROJECT_RESOURCES_DONE)]
        http_mocks.mock_http_response_sequence(mock_responses)

        with mock.patch.object(self.asset_api_client,
                               'OPERATION_DELAY_IN_SEC', 0.1):
            with self.assertRaises(api_errors.OperationTimeoutError):
                result = self.asset_api_client.export_assets(
                    fake_cloudasset.PROJECT, fake_cloudasset.DESTINATION,
                    content_type='RESOURCE', blocking=True, timeout=0.1)

    def test_export_assets_http_error(self):
        """Test export_assets with a permission denied error."""
        http_mocks.mock_http_response(fake_cloudasset.PERMISSION_DENIED, 403)
        with self.assertRaises(api_errors.ApiExecutionError):
            self.asset_api_client.export_assets(
                fake_cloudasset.PROJECT, fake_cloudasset.DESTINATION,
                content_type='RESOURCE', blocking=True)

    def test_export_assets_valueerror(self):
        """Test export_assets for an invalid parent."""
        with self.assertRaises(ValueError):
            self.asset_api_client.export_assets(
                'serviceaccounts/123454321', fake_cloudasset.DESTINATION,
                content_type='RESOURCE')

    def test_get_operation_http_error(self):
        """Test get_operation with a permission denied error."""
        http_mocks.mock_http_response(fake_cloudasset.PERMISSION_DENIED, 403)
        with self.assertRaises(api_errors.ApiExecutionError):
            self.asset_api_client.get_operation(
                fake_cloudasset.PROJECT_OPERATION)

    def test_get_operation_valueerror(self):
        """Test get_operation for an invalid parent."""
        with self.assertRaises(ValueError):
            self.asset_api_client.get_operation(
                'serviceaccounts/123454321/operations/ExportAssets/123456789')


if __name__ == '__main__':
    unittest.main()
