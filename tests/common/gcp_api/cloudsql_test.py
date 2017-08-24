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

"""Tests the CloudSQL API client."""

import json
import unittest
import mock
from oauth2client import client

from tests.common.gcp_api.test_data import http_mocks
from tests.common.gcp_type.test_data import fake_cloudsql
from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import cloudsql
from google.cloud.security.common.gcp_api import errors as api_errors


# pylint: disable=bad-indentation
class CloudsqlTest(ForsetiTestCase):
    """Test the CloudSQL Client."""

    @classmethod
    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {'max_sqladmin_api_calls_per_100_seconds': 10000}
        cls.sql_api_client = cloudsql.CloudsqlClient(
            global_configs=fake_global_configs, use_rate_limiter=False)
        cls.project_id = 111111

    @mock.patch.object(client, 'GoogleCredentials')
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
