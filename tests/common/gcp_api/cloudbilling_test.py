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

"""Tests the CloudBilling API client."""
import unittest
import mock
from oauth2client import client

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_cloudbilling_responses as fake_cloudbilling
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import cloudbilling
from google.cloud.forseti.common.gcp_api import errors as api_errors


class CloudBillingTest(unittest_utils.ForsetiTestCase):
    """Test the CloudSQL Client."""

    @classmethod
    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'max_cloudbilling_api_calls_per_60_seconds': 10000}
        cls.billing_api_client = cloudbilling.CloudBillingClient(
            global_configs=fake_global_configs, use_rate_limiter=False)
        cls.project_id = fake_cloudbilling.FAKE_PROJECT_ID

    @mock.patch.object(client, 'GoogleCredentials')
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        billing_api_client = cloudbilling.CloudBillingClient(global_configs={})
        self.assertEqual(None, billing_api_client.repository._rate_limiter)

    def test_get_billing_info(self):
        """Test get project billing info."""
        http_mocks.mock_http_response(
            fake_cloudbilling.GET_PROJECTS_BILLING_INFO)

        result = self.billing_api_client.get_billing_info(self.project_id)

        self.assertEquals(self.project_id, result['projectId'])

    def test_get_billing_info_raises(self):
        """Test get project billing info raises on exception."""
        http_mocks.mock_http_response(fake_cloudbilling.PERMISSION_DENIED,
                                      '403')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.billing_api_client.get_billing_info(self.project_id)

    def test_get_billing_info_not_found(self):
        """Test get project billing info handles project not found error."""
        http_mocks.mock_http_response(fake_cloudbilling.PROJECT_NOT_FOUND,
                                      '404')
        result = self.billing_api_client.get_billing_info(self.project_id)

        self.assertEquals({}, result)


if __name__ == '__main__':
    unittest.main()
