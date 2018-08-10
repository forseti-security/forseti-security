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

"""Tests the CloudSQL API client."""
import json
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import http_mocks
from tests.common.gcp_api.test_data import fake_cloudsql_responses as fake_cloudsql
from google.cloud.forseti.common.gcp_api import cloudsql
from google.cloud.forseti.common.gcp_api import errors as api_errors


class CloudsqlTest(unittest_utils.ForsetiTestCase):
    """Test the CloudSQL Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'sqladmin': {'max_calls': 1, 'period': 1.1}}
        cls.sql_api_client = cloudsql.CloudsqlClient(
            global_configs=fake_global_configs, use_rate_limiter=False)
        cls.project_id = 111111

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        sql_api_client = cloudsql.CloudsqlClient(global_configs={})
        self.assertEqual(None, sql_api_client.repository._rate_limiter)

    def test_get_instances(self):
        """Test get cloudsql instances."""
        http_mocks.mock_http_response(
            json.dumps(fake_cloudsql.FAKE_CLOUDSQL_RESPONSE))

        result = self.sql_api_client.get_instances(self.project_id)

        self.assertEquals(fake_cloudsql.EXPECTED_FAKE_CLOUDSQL_FROM_API, result)

    def test_get_instances_empty(self):
        """Test get cloudsql instances."""
        http_mocks.mock_http_response(fake_cloudsql.FAKE_EMPTY_RESPONSE)

        result = self.sql_api_client.get_instances(self.project_id)

        self.assertEquals([], result)

    def test_get_instances_raises(self):
        """Test get cloudsql instances."""
        http_mocks.mock_http_response(fake_cloudsql.PROJECT_INVALID, '400')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.sql_api_client.get_instances(self.project_id)


if __name__ == '__main__':
    unittest.main()
