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

"""Tests the Bigquery client."""

import json
import mock
import httplib2
import unittest

from googleapiclient.errors import HttpError
from googleapiclient import http

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import bigquery as bq
from google.cloud.security.common.gcp_api import _base_repository
from google.cloud.security.common.gcp_api import errors as api_errors
from tests.common.gcp_api.test_data import fake_bigquery as fbq


# pylint: disable=bad-indentation
class BigqueryTestCase(ForsetiTestCase):
    """Test the Bigquery API Client."""

    @mock.patch('google.cloud.security.common.gcp_api._base_client.GoogleCredentials')
    def setUp(self, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'max_bigquery_api_calls_per_100_seconds': 1000000}
        self.bq_api_client = bq.BigQueryClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

        self.http_response = httplib2.Response(
                {'status': '400', 'content-type': 'application/json'}
        )

    def mock_http_response(self, response, status='200'):
        """Set the mock response to an http request."""
        http_mock = http.HttpMock()
        http_mock.response_headers = {'status': status}
        http_mock.data = response
        _base_repository.LOCAL_THREAD.http = http_mock

    def mock_http_response_sequence(self, responses):
        """Set the mock response to an http request."""
        http_mock = http.HttpMockSequence(responses)
        _base_repository.LOCAL_THREAD.http = http_mock

    def test_get_bigquery_projectids_raises(self):
        """Test that get_bigquery_projectids raises on HTTP exception."""
        self.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_bigquery_projectids()

    def test_get_bigquery_projectids_with_no_projects(self):
        """Test that get_bigquery_projectids returns an emptly list."""
        mock_responses = []
        for page in fbq.PROJECTS_LIST_REQUEST_RESPONSE_EMPTY:
            mock_responses.append(({'status': '200'}, json.dumps(page)))
        self.mock_http_response_sequence(mock_responses)

        return_value = self.bq_api_client.get_bigquery_projectids()

        self.assertListEqual([], return_value)

    def test_get_bigquery_projectids(self):
        """Test get_bigquery_projectids returns a valid list of project ids."""
        mock_responses = []
        for page in fbq.PROJECTS_LIST_REQUEST_RESPONSE:
            mock_responses.append(({'status': '200'}, json.dumps(page)))
        self.mock_http_response_sequence(mock_responses)

        return_value = self.bq_api_client.get_bigquery_projectids()

        self.assertListEqual(fbq.PROJECTS_LIST_EXPECTED, return_value)

    def test_get_datasets_for_projectid_raises(self):
        """Test get_datasets_for_projectid raises on HTTP exception."""
        self.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.bq_api_client.get_datasets_for_projectid(fbq.PROJECT_IDS[0])

    def test_get_datasets_for_projectid(self):
        """Test get_datasets_for_projectid returns datasets properly."""
        self.mock_http_response(fbq.DATASETS_LIST_REQUEST_RESPONSE)
        project_id = fbq.PROJECT_IDS[0]

        return_value = self.bq_api_client.get_datasets_for_projectid(project_id)

        self.assertListEqual(return_value, fbq.DATASETS_LIST_EXPECTED)

    def test_get_dataset_access_raises(self):
        """Test get_dataset_access raises when there is an HTTP exception."""
        self.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_dataset_access(fbq.PROJECT_IDS[0],
                                                  fbq.DATASET_ID)

    def test_get_dataset_access(self):
        """Test get_dataset_access returns dataset ACLs properly."""
        self.mock_http_response(fbq.DATASETS_GET_REQUEST_RESPONSE)

        return_value = self.bq_api_client.get_dataset_access(fbq.PROJECT_IDS[0],
                                                             fbq.DATASET_ID)

        self.assertListEqual(return_value, fbq.DATASETS_GET_EXPECTED)


if __name__ == '__main__':
    unittest.main()
