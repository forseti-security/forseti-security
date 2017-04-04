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

from google.apputils import basetest
from google.cloud.security.common.gcp_api import _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import storage


class StorageTest(basetest.TestCase):
    """Test the StorageClient."""

    @mock.patch.object(_base_client.BaseClient, '__init__', autospec=True)
    def test_get_bucket_and_path_from(self, mock_base):
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


if __name__ == '__main__':
    basetest.main()
