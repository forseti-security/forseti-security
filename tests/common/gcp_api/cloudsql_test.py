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
from google.cloud.security.common.gcp_api import cloudsql
from tests.common.gcp_type.test_data import fake_cloudsql


from pprint import pprint as pp


class CloudsqlTest(basetest.TestCase):
    """Test the StorageClient."""

    @mock.patch('google.cloud.security.common.gcp_api._base_client.discovery')
    @mock.patch('google.cloud.security.common.gcp_api._base_client.GoogleCredentials')
    def setUp(self, mock_google_credential, mock_discovery):
        """Set up."""
        fake_global_configs = {'max_sqladmin_api_calls_per_100_seconds': 88888}
        self.sql_api_client = cloudsql.CloudsqlClient(
            global_configs=fake_global_configs)

    def test_get_instances(self):
        """Test get cloudsql instances."""
        project_number = '11111'
        mock_cloudsql_stub = mock.MagicMock()
        self.sql_api_client.service = mock.MagicMock()
        self.sql_api_client.service.instances.return_value = mock_cloudsql_stub

        fake_cloudsql_response = fake_cloudsql.FAKE_CLOUDSQL_RESPONSE
        expected_cloudsql = fake_cloudsql.EXPECTED_FAKE_CLOUDSQL_FROM_API

        self.sql_api_client.get_instances = mock.MagicMock(
            return_value=fake_cloudsql_response)
        
        result = [self.sql_api_client.get_instances(project_number)]

        self.assertEquals(expected_cloudsql, result)


if __name__ == '__main__':
    basetest.main()
