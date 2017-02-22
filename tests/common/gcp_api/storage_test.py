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
from google.cloud.security.common.gcp_api._base_client import _BaseClient
from google.cloud.security.common.gcp_api.errors import InvalidBucketPathError
from google.cloud.security.common.gcp_api.storage import StorageClient
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil

class StorageTest(basetest.TestCase):

    def setUp(self):
        pass

    @mock.patch.object(_BaseClient, '__init__', autospec=True)
    def test_get_bucket_and_path_from(self, mock_base):
        """Given a valid bucket object path, return the bucket and path."""
        expected_bucket = 'my-bucket'
        expected_obj_path = 'path/to/object'
        test_path = 'gs://{}/{}'.format(expected_bucket, expected_obj_path)
        client = StorageClient()
        bucket, obj_path = client.get_bucket_and_path_from(test_path)
        self.assertEqual(expected_bucket, bucket)
        self.assertEqual(expected_obj_path, obj_path)

    @mock.patch.object(_BaseClient, '__init__', autospec=True)
    def test_non_bucket_uri_raises(self, mock_base):
        """Given a valid bucket object path, return the bucket and path."""
        test_path = '/some/local/path/file.ext'
        client = StorageClient()
        with self.assertRaises(InvalidBucketPathError):
            bucket, obj_path = client.get_bucket_and_path_from(test_path)


if __name__ == '__main__':
    basetest.main()
