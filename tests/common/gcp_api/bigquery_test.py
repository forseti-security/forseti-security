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

"""Tests the Bigquery client."""
import json
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_bigquery as fbq
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import bigquery as bq
from google.cloud.forseti.common.gcp_api import errors as api_errors


class BigqueryTestCase(unittest_utils.ForsetiTestCase):
    """Test the Bigquery API Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'bigquery': {'max_calls': 160, 'period': 1}}
        cls.bq_api_client = bq.BigQueryClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        bq_api_client = bq.BigQueryClient(global_configs={})
        self.assertEqual(None, bq_api_client.repository._rate_limiter)

    def test_get_bigquery_projectids_raises(self):
        """Test that get_bigquery_projectids raises on HTTP exception."""
        http_mocks.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_bigquery_projectids()

    def test_get_bigquery_projectids_with_no_projects(self):
        """Test that get_bigquery_projectids returns an emptly list."""
        mock_responses = []
        for page in fbq.PROJECTS_LIST_REQUEST_RESPONSE_EMPTY:
            mock_responses.append(({'status': '200'}, json.dumps(page)))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.bq_api_client.get_bigquery_projectids()

        self.assertListEqual([], return_value)

    def test_get_bigquery_projectids(self):
        """Test get_bigquery_projectids returns a valid list of project ids."""
        mock_responses = []
        for page in fbq.PROJECTS_LIST_REQUEST_RESPONSE:
            mock_responses.append(({'status': '200'}, json.dumps(page)))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.bq_api_client.get_bigquery_projectids()

        self.assertListEqual(fbq.PROJECTS_LIST_EXPECTED, return_value)

    def test_get_datasets_for_projectid_raises(self):
        """Test get_datasets_for_projectid raises on HTTP exception."""
        http_mocks.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.bq_api_client.get_datasets_for_projectid(fbq.PROJECT_IDS[0])

    def test_get_datasets_for_projectid(self):
        """Test get_datasets_for_projectid returns datasets properly."""
        http_mocks.mock_http_response(fbq.DATASETS_LIST_REQUEST_RESPONSE)
        project_id = fbq.PROJECT_IDS[0]

        return_value = self.bq_api_client.get_datasets_for_projectid(project_id)

        self.assertListEqual(return_value, fbq.DATASETS_LIST_EXPECTED)

    def test_get_dataset_access_raises(self):
        """Test get_dataset_access raises when there is an HTTP exception."""
        http_mocks.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_dataset_access(fbq.PROJECT_IDS[0],
                                                  fbq.DATASET_ID)

    def test_get_dataset_access(self):
        """Test get_dataset_access returns dataset ACLs properly."""
        http_mocks.mock_http_response(fbq.DATASETS_GET_REQUEST_RESPONSE)

        return_value = self.bq_api_client.get_dataset_access(fbq.PROJECT_IDS[0],
                                                             fbq.DATASET_ID)

        self.assertListEqual(return_value, fbq.DATASETS_GET_EXPECTED)

    def test_get_tables(self):
        """Test get_tables returns tables properly."""
        mock_responses = []
        for page in fbq.GET_TABLES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        return_value = self.bq_api_client.get_tables(fbq.PROJECT_IDS[0],
                                                     fbq.DATASET_ID)

        self.assertListEqual(return_value, fbq.TABLES_GET_EXPECTED)

    def test_get_tables_access_raises(self):
        """Test get_dataset_access raises when there is an HTTP exception."""
        http_mocks.mock_http_response(fbq.PERMISSION_DENIED, '403')

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_tables(fbq.PROJECT_IDS[0],
                                          fbq.DATASET_ID)


if __name__ == '__main__':
    unittest.main()
