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
from tests.common.gcp_api.test_data import fake_bigquery_table as fbt
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import bqtable as bt
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import stackdriver_logging
from google.cloud.forseti.common.gcp_api import cloudbilling


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
            'cloudbilling': {'max_calls': 5, 'period': 1.2}}
        cls.bqtable_client = bt.BqtableClient(
            global_configs=fake_global_configs, use_rate_limiter=False)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        bqtable_client = bt.BqtableClient(global_configs={})
        self.assertEqual(None, bqtable_client.repository._rate_limiter)

    def test_get_tables(self):
        """Test get bigquery dataset tables."""
        mock_responses = []
        for page in fbt.GET_TABLES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.bqtable_client.get_tables('123','456')

if __name__ == '__main__':
    unittest.main()
