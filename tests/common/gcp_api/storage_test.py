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

"""Tests the Storage client."""
import unittest
import mock
import google.auth
from google.oauth2 import credentials
import StringIO

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_storage_responses as fake_storage
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import metadata_server


class StorageTest(unittest_utils.ForsetiTestCase):
    """Test the StorageClient."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    @mock.patch.object(metadata_server, 'get_project_id', spec=True)
    @mock.patch.object(metadata_server, 'can_reach_metadata_server', spec=True)
    def setUpClass(cls, mock_reach_metadata, mock_get_project_id,
                   mock_google_credential):
        """Set up."""
        mock_reach_metadata.return_value = True
        mock_get_project_id.return_value = 'test-project'
        cls.gcs_api_client = storage.StorageClient({})

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
            storage.get_bucket_and_path_from(test_path)

        with self.assertRaises(api_errors.InvalidBucketPathError):
            storage.get_bucket_and_path_from(None)

    def test_get_buckets(self):
        """Test get buckets."""
        mock_responses = []
        for page in fake_storage.GET_BUCKETS_RESPONSES:
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

    def test_get_bucket_acls(self):
        """Test get bucket acls."""
        http_mocks.mock_http_response(
            fake_storage.GET_BUCKET_ACL)

        results = self.gcs_api_client.get_bucket_acls(
            fake_storage.FAKE_BUCKET_NAME)
        self.assertEqual(3, len(results))

    def test_get_buckets_acls_raises(self):
        """Test get buckets acls access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.gcs_api_client.get_bucket_acls(fake_storage.FAKE_BUCKET_NAME)

    def test_get_buckets_acls_user_project(self):
        """Test get buckets acls requires user project."""
        mock_responses = [
            ({'status': '400', 'content-type': 'application/json'},
             fake_storage.USER_PROJECT_MISSING),
            ({'status': '200', 'content-type': 'application/json'},
             fake_storage.GET_BUCKET_ACL),
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gcs_api_client.get_bucket_acls(
            fake_storage.FAKE_BUCKET_NAME)
        self.assertEqual(3, len(results))

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
                fake_storage.FAKE_BUCKET_NAME)

    def test_get_bucket_iam_policy_user_project(self):
        """Test get bucket iam policy requires user project."""
        mock_responses = [
            ({'status': '400', 'content-type': 'application/json'},
             fake_storage.USER_PROJECT_MISSING),
            ({'status': '200', 'content-type': 'application/json'},
             fake_storage.GET_BUCKET_IAM_POLICY_RESPONSE),
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gcs_api_client.get_bucket_iam_policy(
            fake_storage.FAKE_BUCKET_NAME)
        self.assertTrue('bindings' in results)

    def test_get_default_object_acls(self):
        """Test get default object acls."""
        http_mocks.mock_http_response(
            fake_storage.DEFAULT_OBJECT_ACL)

        results = self.gcs_api_client.get_default_object_acls(
            fake_storage.FAKE_BUCKET_NAME)
        self.assertEqual(3, len(results))

    def test_get_default_object_acls_raises(self):
        """Test get default object acls access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.gcs_api_client.get_default_object_acls(
                 fake_storage.FAKE_BUCKET_NAME)

    def test_get_default_object_acls_user_project(self):
        """Test get default object acls requires user project."""
        mock_responses = [
            ({'status': '400', 'content-type': 'application/json'},
             fake_storage.USER_PROJECT_MISSING),
            ({'status': '200', 'content-type': 'application/json'},
             fake_storage.DEFAULT_OBJECT_ACL),
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gcs_api_client.get_default_object_acls(
            fake_storage.FAKE_BUCKET_NAME)
        self.assertEqual(3, len(results))

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

    def test_get_objects_user_project(self):
        """Test get objects requires user project."""
        mock_responses = [
            ({'status': '400', 'content-type': 'application/json'},
             fake_storage.USER_PROJECT_MISSING)]

        for page in fake_storage.LIST_OBJECTS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        expected_object_names = fake_storage.EXPECTED_FAKE_OBJECT_NAMES

        results = self.gcs_api_client.get_objects(
            fake_storage.FAKE_PROJECT_NUMBER)
        self.assertEquals(expected_object_names,
                          [r.get('name') for r in results])

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

    def test_get_object_iam_policy_user_project(self):
        """Test get object iam policy requires user project."""
        mock_responses = [
            ({'status': '400', 'content-type': 'application/json'},
             fake_storage.USER_PROJECT_MISSING),
            ({'status': '200', 'content-type': 'application/json'},
             fake_storage.GET_OBJECT_IAM_POLICY_RESPONSE),
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gcs_api_client.get_object_iam_policy(
            fake_storage.FAKE_BUCKET_NAME, fake_storage.FAKE_OBJECT_NAME)
        self.assertTrue('bindings' in results)

    def test_get_object_acls(self):
        """Test get object acls."""
        http_mocks.mock_http_response(
            fake_storage.GET_OBJECT_ACL)

        results = self.gcs_api_client.get_object_acls(
            fake_storage.FAKE_BUCKET_NAME, fake_storage.FAKE_OBJECT_NAME)
        self.assertEqual(4, len(results))

    def test_get_objects_iam_policy_raises(self):
        """Test get object acls access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.gcs_api_client.get_object_acls(
                fake_storage.FAKE_BUCKET_NAME, fake_storage.FAKE_OBJECT_NAME)

    def test_get_object_acls_user_project(self):
        """Test get object acls requires user project."""
        mock_responses = [
            ({'status': '400', 'content-type': 'application/json'},
             fake_storage.USER_PROJECT_MISSING),
            ({'status': '200', 'content-type': 'application/json'},
             fake_storage.GET_OBJECT_ACL),
        ]

        results = self.gcs_api_client.get_object_acls(
            fake_storage.FAKE_BUCKET_NAME, fake_storage.FAKE_OBJECT_NAME)
        self.assertEqual(4, len(results))


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

    def test_download(self):
        """Test download file returns a valid response."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-2/5'}, b'123'),
            ({'status': '200',
              'content-range': '3-4/5'}, b'45')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        expected_result = b'12345'
        output_file = StringIO.StringIO()
        file_size = self.gcs_api_client.download(
            'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                fake_storage.FAKE_OBJECT_NAME),
            output_file=output_file)
        self.assertEqual(len(expected_result), file_size)
        self.assertEqual(expected_result, output_file.getvalue())
        output_file.close()

    def test_download_raises(self):
        """Test download file returns not found error."""
        http_mocks.mock_http_response(fake_storage.NOT_FOUND, '404')
        output_file = StringIO.StringIO()
        with self.assertRaises(storage.errors.HttpError):
            self.gcs_api_client.download(
                'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                    fake_storage.FAKE_OBJECT_NAME),
                output_file=output_file)
        self.assertEqual('', output_file.getvalue())
        output_file.close()

    def test_upload_text_file(self):
        """Test upload text file."""
        http_mocks.mock_http_response(u'{}')

        with unittest_utils.create_temp_file(b'12345') as temp_file:
            result = self.gcs_api_client.put_text_file(
                temp_file,
                'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                    fake_storage.FAKE_OBJECT_NAME))
        self.assertEqual({}, result)

    def test_upload_text_file_raises(self):
        """Test upload text access forbidden."""
        http_mocks.mock_http_response(fake_storage.ACCESS_FORBIDDEN, '403')

        with self.assertRaises(storage.errors.HttpError):
            with unittest_utils.create_temp_file(b'12345') as temp_file:
                self.gcs_api_client.put_text_file(
                    temp_file,
                    'gs://{}/{}'.format(fake_storage.FAKE_BUCKET_NAME,
                                        fake_storage.FAKE_OBJECT_NAME))


if __name__ == '__main__':
    unittest.main()
