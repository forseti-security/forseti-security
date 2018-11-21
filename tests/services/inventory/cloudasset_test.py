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
"""Unit Tests: Cloud Asset API integration for Forseti Server."""

import os
import unittest
from googleapiclient import errors
import httplib2
import mock
import google.auth
from google.oauth2 import credentials
from sqlalchemy.orm import sessionmaker

from tests.services.util.db import create_test_engine_with_file
from tests import unittest_utils

from google.cloud.forseti.common.gcp_api import cloudasset as cloudasset_api
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.services.base.config import InventoryConfig
from google.cloud.forseti.services.inventory import storage
from google.cloud.forseti.services.inventory.base import cloudasset

TEST_RESOURCE_DIR_PATH = os.path.join(
    os.path.dirname(__file__), 'test_data')

PERMISSION_DENIED = """
{
  "error": {
    "code": 403,
    "message": "The caller does not have permission",
    "status": "PERMISSION_DENIED",
  }
}
"""

EXPORT_ASSETS_ERROR = """
{
  "name": "organizations/9876543210/operations/ExportAssets/567890987654321",
  "metadata": {
    "@type": "type.googleapis.com/google.cloud.asset.v1beta1.ExportAssetsRequest",
    "parent": "organizations/9876543210",
    "contentType": "IAM_POLICY",
    "outputConfig": {
      "gcsDestination": {
        "uri": "gs://forseti-test-bucket/test-export.txt"
      }
    }
  },
  "done": true,
  "error": {
    "code": 13,
    "message": "Snapshot or asset write failed"
  }
}
"""


class InventoryCloudAssetTest(unittest_utils.ForsetiTestCase):
    """Test CloudAsset data loader."""

    def setUp(self):
        """Setup method."""
        unittest_utils.ForsetiTestCase.setUp(self)
        self.engine, self.dbfile = create_test_engine_with_file()
        _session_maker = sessionmaker()
        self.session = _session_maker(bind=self.engine)
        storage.initialize(self.engine)
        self.inventory_config = InventoryConfig('organizations/987654321',
                                                '',
                                                {},
                                                0,
                                                {'enabled': True,
                                                 'gcs_path': 'gs://test-bucket'}
                                               )

        # Ensure test data doesn't get deleted
        self.mock_unlink = mock.patch.object(
            os, 'unlink', autospec=True).start()
        self.mock_export_assets = mock.patch.object(
            cloudasset_api.CloudAssetClient,
            'export_assets',
            autospec=True).start()
        self.mock_copy_file_from_gcs = mock.patch.object(
            file_loader,
            'copy_file_from_gcs',
            autospec=True).start()
        self.mock_auth = mock.patch.object(
            google.auth,
            'default',
            return_value=(mock.Mock(
                spec_set=credentials.Credentials), 'test-project')).start()

    def tearDown(self):
        """tearDown."""
        unittest_utils.ForsetiTestCase.tearDown(self)
        mock.patch.stopall()

        # Stop mocks before unlinking the database file.
        os.unlink(self.dbfile)

    def validate_data_in_table(self):
        """Validate there is actual data in the CAI table."""
        resource = storage.CaiDataAccess.fetch_cai_asset(
            storage.ContentTypes.resource,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/organizations/111222333',
            self.session)
        expected_resource = {
            'creationTime': '2015-09-09T19:34:18.591Z',
            'displayName': 'forseti.test',
            'lifecycleState': 'ACTIVE',
            'name': 'organizations/111222333',
            'owner': {'directoryCustomerId': 'ABC123DEF'}}
        self.assertEqual(expected_resource, resource)

        iam_policy = storage.CaiDataAccess.fetch_cai_asset(
            storage.ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/folders/1033',
            self.session)
        expected_iam_policy = {
            'bindings': [
                {'members': ['user:a_user@forseti.test'],
                 'role': 'roles/resourcemanager.folderAdmin'}],
            'version': 1}
        self.assertEqual(expected_iam_policy, iam_policy)

    def validate_no_data_in_table(self):
        """Validate there is not data in the CAI table."""
        resource = storage.CaiDataAccess.fetch_cai_asset(
            storage.ContentTypes.resource,
            'google.cloud.resourcemanager.Organization',
            '//cloudresourcemanager.googleapis.com/organizations/111222333',
            self.session)
        expected_resource = {}
        self.assertEqual(expected_resource, resource)

        iam_policy = storage.CaiDataAccess.fetch_cai_asset(
            storage.ContentTypes.iam_policy,
            'google.cloud.resourcemanager.Folder',
            '//cloudresourcemanager.googleapis.com/folders/1033',
            self.session)
        expected_iam_policy = {}
        self.assertEqual(expected_iam_policy, iam_policy)

    def test_get_gcs_path(self):
        """Validate _get_gcs_path returns expected values."""
        result = cloudasset._get_gcs_path('gs://test-bucket',
                                          'RESOURCE',
                                          'organizations/987654321',
                                          1234567890)
        expected_result = (
            'gs://test-bucket/organizations-987654321-resource-1234567890.dump')
        self.assertEqual(expected_result, result)

    def test_load_cloudasset_data(self):
        """Validate load_cloudasset_data correctly dumps and imports data."""
        # Ignore call to export_assets for this test.
        self.mock_export_assets.return_value = {'done': True}

        # Mock copy_file_from_gcs to return correct test data file
        def _copy_file_from_gcs(file_path, *args, **kwargs):
            """Fake copy_file_from_gcs."""
            if 'resource' in file_path:
                return os.path.join(TEST_RESOURCE_DIR_PATH,
                                    'mock_cai_resources.dump')
            elif 'iam_policy' in file_path:
                return os.path.join(TEST_RESOURCE_DIR_PATH,
                                    'mock_cai_iam_policies.dump')

        self.mock_copy_file_from_gcs.side_effect = _copy_file_from_gcs

        results = cloudasset.load_cloudasset_data(self.session,
                                                  self.inventory_config)
        self.assertTrue(results)
        self.validate_data_in_table()

    def test_long_resource_name(self):
        """Validate load_cloudasset_data handles resources with long names."""
        # Ignore call to export_assets for this test.
        self.mock_export_assets.return_value = {'done': True}

        # Mock copy_file_from_gcs to return correct test data file
        def _copy_file_from_gcs(file_path, *args, **kwargs):
            """Fake copy_file_from_gcs."""
            if 'resource' in file_path:
                return os.path.join(
                    TEST_RESOURCE_DIR_PATH,
                    'mock_cai_long_resource_name.dump')
            elif 'iam_policy' in file_path:
                return os.path.join(TEST_RESOURCE_DIR_PATH,
                                    'mock_cai_empty_iam_policies.dump')

        self.mock_copy_file_from_gcs.side_effect = _copy_file_from_gcs

        results = cloudasset.load_cloudasset_data(self.session,
                                                  self.inventory_config)
        # Expect only the resource with the short name got imported.
        expected_results = 1
        self.assertEqual(results, expected_results)

        # Validate resource with short name is in database.
        resource = storage.CaiDataAccess.fetch_cai_asset(
            storage.ContentTypes.resource,
            'google.spanner.Instance',
            '//spanner.googleapis.com/projects/project2/instances/test123',
            self.session)
        expected_resource = {
            'config': 'projects/project2/instanceConfigs/regional-us-east1',
            'displayName': 'Test123',
            'name': 'projects/project2/instances/test123',
            'nodeCount': 1,
            'state': 'READY'}
        self.assertEqual(expected_resource, resource)

    def test_load_cloudasset_data_cai_apierror(self):
        """Validate load_cloud_asset handles an API error from CAI."""
        response = httplib2.Response(
            {'status': '403', 'content-type': 'application/json'})
        content = PERMISSION_DENIED
        error_403 = errors.HttpError(response, content)

        self.mock_export_assets.side_effect = (
            api_errors.ApiExecutionError('organizations/987654321', error_403)
        )
        results = cloudasset.load_cloudasset_data(self.session,
                                                  self.inventory_config)
        self.assertIsNone(results)
        self.assertFalse(self.mock_copy_file_from_gcs.called)
        self.validate_no_data_in_table()

    def test_load_cloudasset_data_cai_timeout(self):
        """Validate load_cloud_asset handles a timeout error."""
        self.mock_export_assets.side_effect = (
            api_errors.OperationTimeoutError('organizations/987654321', {}))
        results = cloudasset.load_cloudasset_data(self.session,
                                                  self.inventory_config)
        self.assertIsNone(results)
        self.assertFalse(self.mock_copy_file_from_gcs.called)
        self.validate_no_data_in_table()

    def test_load_cloudasset_data_cai_error_response(self):
        """Validate load_cloud_asset handles an error result from CAI."""
        self.mock_export_assets.return_value = EXPORT_ASSETS_ERROR
        results = cloudasset.load_cloudasset_data(self.session,
                                                  self.inventory_config)
        self.assertIsNone(results)
        self.assertFalse(self.mock_copy_file_from_gcs.called)
        self.validate_no_data_in_table()

    def test_load_cloudasset_data_download_error(self):
        """Validate load_cloud_asset handles an error downloading from GCS."""
        # Ignore call to export_assets for this test.
        self.mock_export_assets.return_value = {'done': True}

        response = httplib2.Response(
            {'status': '403', 'content-type': 'application/json'})
        content = PERMISSION_DENIED
        error_403 = errors.HttpError(response, content)
        self.mock_copy_file_from_gcs.side_effect = error_403

        results = cloudasset.load_cloudasset_data(self.session,
                                                  self.inventory_config)
        self.assertIsNone(results)
        self.validate_no_data_in_table()

if __name__ == '__main__':
    unittest.main()
