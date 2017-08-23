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

import os
import tempfile
import contextlib

import mock
from oauth2client import client
import unittest

from tests.common.gcp_api.test_data import fake_storage_responses as fake_storage
from tests.common.gcp_api.test_data import http_mocks
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.gcp_api import storage

@contextlib.contextmanager
def create_temp_file(data):
    temp = tempfile.NamedTemporaryFile(delete=False)
    temp.write(data)
    temp.close()
    try:
        yield temp.name
    finally:
        os.unlink(temp.name)

class StorageTest(ForsetiTestCase):
    """Test the StorageClient."""

    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUp(self, mock_google_credential):
        """Set up."""
        self.gcs_api_client = storage.StorageClient()

    def test_get_bucket_and_path_from(self):
        """Given a valid bucket object path, return the bucket and path."""
        test_path = 'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                        fake_storage.FAKE_OBJECT_NAME)
        bucket, obj_name = storage.get_bucket_and_path_from(test_path)
        self.assertEqual(fake_storage.FAKE_BUCKET_NAME, bucket)
        self.assertEqual(fake_storage.FAKE_OBJECT_NAME, obj_name)

    def test_non_bucket_uri_raises(self):
        """Raise exception on invalid paths."""
        test_path = '/some/local/path/file.ext'
        with self.assertRaises(api_errors.InvalidBucketPathError):
            bucket, obj_path = storage.get_bucket_and_path_from(test_path)

        with self.assertRaises(api_errors.InvalidBucketPathError):
            bucket, obj_path = storage.get_bucket_and_path_from(None)

    def test_get_buckets(self):
        """Test get buckets."""
        mock_responses = []
        for page in fake_storage.LIST_FOLDERS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        expected_bucket_names = fake_storage.EXPECTED_FAKE_BUCKET_NAMES

        results = self.gcs_api_client.get_buckets(
            fake_storage.FAKE_PROJECT_NUMBER)
        self.assertEquals(expected_bucket_names,
                          [r.get('name') for r in results])

    def test_get_buckets_raises(self):
        """Test get buckets access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.gcs_api_client.get_buckets(fake_storage.FAKE_PROJECT_NUMBER)

    def test_get_bucket_iam_policy(self):
        """Test get bucket iam policy."""
        http_mocks.mock_http_response(
            fake_storage.GET_BUCKET_IAM_POLICY_RESPONSE)

        results = self.gcs_api_client.get_bucket_iam_policy(
            fake_storage.FAKE_BUCKET_NAME)
        self.assertTrue('bindings' in results)

    def test_get_buckets_iam_policy_raises(self):
        """Test get buckets iam policy access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.gcs_api_client.get_bucket_iam_policy(
                 fake_storage.FAKE_PROJECT_NUMBER)

    def test_get_objects(self):
        """Test get objects."""
        mock_responses = []
        for page in fake_storage.LIST_OBJECTS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        expected_object_names = fake_storage.EXPECTED_FAKE_OBJECT_NAMES

        results = self.gcs_api_client.get_objects(
            fake_storage.FAKE_PROJECT_NUMBER)
        self.assertEquals(expected_object_names,
                          [r.get('name') for r in results])

    def test_get_objects_raises(self):
        """Test get objects bucket not found."""
        http_mocks.mock_http_response(fake_storage.NOT_FOUND, '404')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.gcs_api_client.get_objects(fake_storage.FAKE_PROJECT_NUMBER)

    def test_get_object_iam_policy(self):
        """Test get object iam policy."""
        http_mocks.mock_http_response(
            fake_storage.GET_OBJECT_IAM_POLICY_RESPONSE)

        results = self.gcs_api_client.get_object_iam_policy(
            fake_storage.FAKE_BUCKET_NAME, fake_storage.FAKE_OBJECT_NAME)
        self.assertTrue('bindings' in results)

    def test_get_objects_iam_policy_raises(self):
        """Test get objects iam policy access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.gcs_api_client.get_object_iam_policy(
                 fake_storage.FAKE_BUCKET_NAME, fake_storage.FAKE_OBJECT_NAME)

    def test_get_text_file(self):
        """Test get test file returns a valid response."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-2/5'}, b'123'),
            ({'status': '200',
              'content-range': '3-4/5'}, b'45')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        expected_result = b'12345'
        result = self.gcs_api_client.get_text_file(
            'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                fake_storage.FAKE_OBJECT_NAME))
        self.assertEqual(expected_result, result)

    def test_get_text_file_raises(self):
        """Test get test file returns not found error."""
        http_mocks.mock_http_response(fake_storage.NOT_FOUND, '404')

        with self.assertRaises(storage.errors.HttpError):
            self.gcs_api_client.get_text_file(
                'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                    fake_storage.FAKE_OBJECT_NAME))

    def test_upload_text_file(self):
        """Test upload text file."""
        http_mocks.mock_http_response(u'{}')

        with create_temp_file(b'12345') as temp_file:
            result = self.gcs_api_client.put_text_file(
                temp_file,
                'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                    fake_storage.FAKE_OBJECT_NAME))
        self.assertEqual({}, result)

    def test_upload_text_file_raises(self):
        """Test upload text access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(storage.errors.HttpError):
            with create_temp_file(b'12345') as temp_file:
                self.gcs_api_client.put_text_file(
                    temp_file,
                    'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                        fake_storage.FAKE_OBJECT_NAME))


if __name__ == '__main__':
    unittest.main()
