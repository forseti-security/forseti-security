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

import mock
import httplib2

from googleapiclient.errors import HttpError

from google.apputils import basetest
from google.cloud.security.common.gcp_api import bigquery as bq
from google.cloud.security.common.gcp_api import _base_client as _base_client
from google.cloud.security.common.gcp_api import errors as api_errors
from tests.common.gcp_api.test_data import fake_bigquery as fbq

class BigqueryTestCase(basetest.TestCase):
    """Test the Bigquery API Client."""

    MAX_BIGQUERY_API_CALLS_PER_100_SECONDS = 88888

    @mock.patch.object(bq, 'FLAGS')
    @mock.patch.object(_base_client.BaseClient, '__init__', autospec=True)
    def setUp(self, mock_base_client, mock_flags):
        """Set up."""

        mock_flags.max_bigquery_api_calls_per_100_seconds = (
            self.MAX_BIGQUERY_API_CALLS_PER_100_SECONDS)
        self.bq_api_client = bq.BigQueryClient()
        self.http_response = httplib2.Response(
                {'status': '400', 'content-type': 'application/json'}
        )

    def test_api_client_is_initialized(self):
        """Test that the api client is initialized."""

        self.assertEquals(
            self.MAX_BIGQUERY_API_CALLS_PER_100_SECONDS,
            self.bq_api_client.rate_limiter.max_calls)
        self.assertEquals(
            bq.BigQueryClient.DEFAULT_QUOTA_TIMESPAN_PER_SECONDS,
            self.bq_api_client.rate_limiter.period)

    def test_extract_datasets(self):
        return_value = bq.extract_datasets(fbq.DATASET_LISTS)

        self.assertListEqual(fbq.EXPECTED_DATASETS_LISTS,
                             return_value)

    def test_extract_dataset_references(self):
        return_value = bq.extract_dataset_references(
                fbq.EXPECTED_DATASETS_LISTS)

        self.assertListEqual(fbq.EXPECTED_DATASET_REFERENCES,
                             return_value)

    def test_extract_dataset_access(self):
        return_value = bq.extract_dataset_access(fbq.DATASETS)

        self.assertListEqual(fbq.EXPECTED_DATASET_ACCESS,
                             return_value)

    def test_getdatasets_for_projectid_raises(self):
        mock_bq_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.datasets.return_value = mock_bq_stub

        self.bq_api_client._build_paged_result = mock.MagicMock(
            side_effect=HttpError(self.http_response, '{}')
        )

        with self.assertRaises(api_errors.ApiExecutionError):
             self.bq_api_client.get_datasets_for_projectid(fbq.PROJECT_IDS)

    def test_getdatasets_for_projectid(self):
        mock_bq_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.datasets.return_value = mock_bq_stub
        self.bq_api_client._build_paged_result = mock.MagicMock(
                return_value=fbq.DATASET_LISTS
        )

        return_value = self.bq_api_client.get_datasets_for_projectid(
                fbq.PROJECT_IDS[0]
        )

        self.assertListEqual(return_value, fbq.EXPECTED_DATASET_REFERENCES)

    def test_get_dataset_access_raises(self):
        mock_bq_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.datasets.return_value = mock_bq_stub

        self.bq_api_client._build_paged_result = mock.MagicMock(
                side_effect=HttpError(self.http_response, '{}')
        )

        with self.assertRaises(api_errors.ApiExecutionError):
            self.bq_api_client.get_dataset_access(fbq.PROJECT_IDS[0],
                                                  fbq.DATASET_ID)

    def test_get_dataset_access(self):
        mock_bq_stub = mock.MagicMock()
        self.bq_api_client.service = mock.MagicMock()
        self.bq_api_client.service.datasets.return_value = mock_bq_stub
        self.bq_api_client._build_paged_result = mock.MagicMock(
                return_value=fbq.DATASETS
        )

        return_value = self.bq_api_client.get_dataset_access(
                fbq.PROJECT_IDS[0], fbq.DATASET_ID
        )

        self.assertListEqual(return_value, fbq.EXPECTED_DATASET_ACCESS)

if __name__ == '__main__':
    basetest.main()
