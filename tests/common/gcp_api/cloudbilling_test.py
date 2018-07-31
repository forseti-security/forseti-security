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
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_cloudbilling_responses as fake_cloudbilling
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import cloudbilling
from google.cloud.forseti.common.gcp_api import errors as api_errors


class CloudBillingTest(unittest_utils.ForsetiTestCase):
    """Test the CloudSQL Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'cloudbilling': {'max_calls': 5, 'period': 1.2}}
        cls.billing_api_client = cloudbilling.CloudBillingClient(
            global_configs=fake_global_configs, use_rate_limiter=False)
        cls.project_id = fake_cloudbilling.FAKE_PROJECT_ID

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
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

    def test_get_billing_accounts(self):
        """Test get billing accounts without specifying master account."""
        http_mocks.mock_http_response(fake_cloudbilling.GET_BILLING_ACCOUNTS)

        result = self.billing_api_client.get_billing_accounts()

        self.assertEquals(2, len(result))
        self.assertEquals('billingAccounts/000000-111111-222222',
                          result[0]['name'])
        self.assertEquals('billingAccounts/001122-AABBCC-DDEEFF',
                          result[0]['masterBillingAccount'])

        self.assertEquals('billingAccounts/001122-AABBCC-DDEEFF',
                          result[1]['name'])

    def test_get_billing_subaccounts(self):
        """Test get billing accounts under a master account."""
        http_mocks.mock_http_response(fake_cloudbilling.GET_BILLING_SUBACCOUNTS)

        result = self.billing_api_client.get_billing_accounts(
            master_account_id='billingAccounts/001122-AABBCC-DDEEFF')

        self.assertEquals(1, len(result))
        self.assertEquals('billingAccounts/000000-111111-222222',
                          result[0]['name'])
        self.assertEquals('billingAccounts/001122-AABBCC-DDEEFF',
                          result[0]['masterBillingAccount'])

    def test_get_billing_iam_policies(self):
        """Test get billing accounts under a master account."""
        http_mocks.mock_http_response(fake_cloudbilling.GET_BILLING_IAM)

        result = self.billing_api_client.get_billing_acct_iam_policies(
            '001122-AABBCC-DDEEFF')

        self.assertEquals(2, len(result['bindings']))
        self.assertEquals('roles/billing.admin', result['bindings'][0]['role'])
        self.assertEquals('user:foo@example.com',
                          result['bindings'][0]['members'][0])

if __name__ == '__main__':
    unittest.main()
