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

"""Tests the Storage client."""

import mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import storage
from tests.common.gcp_type.test_data import fake_buckets

class StorageTest(ForsetiTestCase):
    """Test the StorageClient."""

    @mock.patch.object(_base_client.BaseClient, '__init__', autospec=True)
    def setUp(self, mock_base_client):
        """Set up."""
        self.gcs_api_client = storage.StorageClient()

    def test_get_bucket_and_path_from(self):
        """Given a valid bucket object path, return the bucket and path."""
        expected_bucket = 'my-bucket'
        expected_obj_path = 'path/to/object'
        test_path = 'gs://{}/{}'.format(expected_bucket, expected_obj_path)
        client = storage.StorageClient()
        bucket, obj_path = storage.get_bucket_and_path_from(test_path)
        self.assertEqual(expected_bucket, bucket)
        self.assertEqual(expected_obj_path, obj_path)

    @mock.patch.object(_base_client.BaseClient, '__init__', autospec=True)
    def test_non_bucket_uri_raises(self, mock_base):
        """Given a valid bucket object path, return the bucket and path."""
        test_path = '/some/local/path/file.ext'
        client = storage.StorageClient()
        with self.assertRaises(api_errors.InvalidBucketPathError):
            bucket, obj_path = storage.get_bucket_and_path_from(test_path)

    def test_get_buckets(self):
        """Test get buckets."""
        project_number = '11111'
        mock_buckets_stub = mock.MagicMock()
        self.gcs_api_client.service = mock.MagicMock()
        self.gcs_api_client.service.buckets.return_value = mock_buckets_stub

        fake_buckets_response = fake_buckets.FAKE_BUCKETS_RESPONSE
        expected_buckets = fake_buckets.EXPECTED_FAKE_BUCKETS_FROM_API

        self.gcs_api_client.get_buckets = mock.MagicMock(
            return_value=fake_buckets_response)
        
        result = list(self.gcs_api_client.get_buckets(project_number))
        self.assertEquals(expected_buckets, [fake_buckets_response])

    def test_get_bucket_acls(self):
        """Test get bucket acls."""
        bucket_name = 'fakebucket1'
        mock_buckets_stub = mock.MagicMock()
        self.gcs_api_client.service = mock.MagicMock()
        self.gcs_api_client.service.bucketAccessControls.return_value = mock_buckets_stub

        fake_bucket_acls_response = fake_buckets.FAKE_BUCKET_ACLS_RESPONSE
        expected_bucket_acls = fake_buckets.EXPECTED_FAKE_BUCKET_ACLS_FROM_API

        self.gcs_api_client.get_buckets = mock.MagicMock(
            return_value=fake_bucket_acls_response)
        
        result = list(self.gcs_api_client.get_bucket_acls(bucket_name))
        self.assertEquals(expected_bucket_acls, [fake_bucket_acls_response])


if __name__ == '__main__':
    unittest.main()
