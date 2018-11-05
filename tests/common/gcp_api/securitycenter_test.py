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

"""Tests the Security Center API client."""
import json
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from google.cloud.forseti.common.gcp_api import securitycenter
from google.cloud.forseti.common.gcp_api import errors as api_errors
from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_securitycenter_responses as fake_cscc
from tests.common.gcp_api.test_data import http_mocks


class SecurityCenterTest(unittest_utils.ForsetiTestCase):
    """Test the Security Center Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'securitycenter': {'max_calls': 1, 'period': 1.1}}
        # securitycenter_alpha_api_client is alpha api client
        cls.securitycenter_alpha_api_client = securitycenter.SecurityCenterClient()
        cls.securitycenter_beta_api_client = securitycenter.SecurityCenterClient(version='v1beta1')
        cls.project_id = 111111
        cls.source_id = 'organizations/111/sources/222'

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        securitycenter_alpha_api_client = securitycenter.SecurityCenterClient()
        self.assertEqual(None, securitycenter_alpha_api_client.repository._rate_limiter)

    def test_create_findings(self):
        """Test create cscc findings."""
        
        http_mocks.mock_http_response(
            json.dumps(fake_cscc.EXPECTED_CREATE_FINDING_RESULT))

        result = self.securitycenter_alpha_api_client.create_finding(
            fake_cscc.FAKE_ALPHA_FINDING, fake_cscc.ORGANIZATION_ID)
        self.assertEquals(fake_cscc.EXPECTED_CREATE_FINDING_RESULT, result)

        result = self.securitycenter_beta_api_client.create_finding(
            'fake finding',
            fake_cscc.ORGANIZATION_ID,
            source_id=self.source_id
            )
        self.assertEquals(fake_cscc.EXPECTED_CREATE_FINDING_RESULT, result)


    def test_create_findings_raises(self):
        """Test create cscc finding raises exception."""
        http_mocks.mock_http_response(fake_cscc.PERMISSION_DENIED, '403')

        # alpha api
        with self.assertRaises(api_errors.ApiExecutionError):
            self.securitycenter_alpha_api_client.create_finding(
                json.loads(fake_cscc.FAKE_ALPHA_FINDING),
                           fake_cscc.ORGANIZATION_ID)

        # beta api
        fake_beta_finding = {'source_properties': {'violation_data': 'foo'}}
        with self.assertRaises(api_errors.ApiExecutionError):
            self.securitycenter_beta_api_client.create_finding(
                fake_beta_finding,
                fake_cscc.ORGANIZATION_ID,
                source_id=self.source_id)

if __name__ == '__main__':
    unittest.main()
