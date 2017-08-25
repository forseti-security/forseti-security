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

"""Tests the Compute client."""
import unittest
import mock
from oauth2client import client
import parameterized

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_compute_responses as fake_compute
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.gcp_api import errors as api_errors

ERROR_TEST_CASES = [
    ('api_not_enabled', fake_compute.API_NOT_ENABLED, '403',
     api_errors.ApiNotEnabledError),
    ('access_denied', fake_compute.ACCESS_DENIED, '403',
     api_errors.ApiExecutionError),
]


class ComputeTest(unittest_utils.ForsetiTestCase):
    """Test the Compute client."""

    @classmethod
    @mock.patch.object(client, 'GoogleCredentials', spec=True)
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {'max_compute_api_calls_per_second': 2000}
        cls.gce_api_client = compute.ComputeClient(
            global_configs=fake_global_configs)
        cls.project_id = fake_compute.FAKE_PROJECT_ID

    @mock.patch.object(client, 'GoogleCredentials')
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        gce_api_client = compute.ComputeClient(global_configs={})
        self.assertEqual(None, gce_api_client.repository._rate_limiter)

    def test_get_backend_services(self):
        """Test get backend services."""
        mock_responses = []
        for page in fake_compute.LIST_BACKEND_SERVICES_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gce_api_client.get_backend_services(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_BACKEND_SERVICES_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_backend_services_errors(self, name, response, status,
                                         expected_exception):
        """Verify error conditions for get backend services."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_backend_services(self.project_id))

    def test_get_forwarding_rules(self):
        """Test get forwarding rules."""
        http_mocks.mock_http_response(
            fake_compute.FORWARDING_RULES_AGGREGATED_LIST)

        results = self.gce_api_client.get_forwarding_rules(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_FORWARDING_RULE_NAMES,
                          [r.get('name') for r in results])

    def test_get_forwarding_rules_by_region(self):
        """Test get forwarding rules by region."""
        http_mocks.mock_http_response(fake_compute.FORWARDING_RULES_LIST)

        results = self.gce_api_client.get_forwarding_rules(
            self.project_id, fake_compute.FAKE_FORWARDING_RULE_REGION)
        self.assertEquals(fake_compute.EXPECTED_FORWARDING_RULE_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_forwarding_rule_errors(self, name, response, status,
                                        expected_exception):
        """Verify error conditions for get forwarding rules."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_forwarding_rules(self.project_id))
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_forwarding_rules(
                self.project_id, fake_compute.FAKE_FORWARDING_RULE_REGION))

    def test_get_firewall_rules(self):
        """Test get firewall rules."""
        mock_responses = []
        for page in fake_compute.LIST_FIREWALLS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gce_api_client.get_firewall_rules(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_FIREWALL_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_firewall_rules_errors(self, name, response, status,
                                       expected_exception):
        """Verify error conditions for get firewall rules."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_firewall_rules(self.project_id))

    def test_get_instances(self):
        """Test get instances."""
        http_mocks.mock_http_response(fake_compute.INSTANCES_AGGREGATED_LIST)

        results = self.gce_api_client.get_instances(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_NAMES,
                          [r.get('name') for r in results])

    def test_get_instances_by_zone(self):
        """Test get instances by zone."""
        http_mocks.mock_http_response(fake_compute.INSTANCES_LIST)

        results = self.gce_api_client.get_instances(
            self.project_id, fake_compute.FAKE_INSTANCE_ZONE)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_instances_errors(self, name, response, status,
                                  expected_exception):
        """Verify error conditions for get instances."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instances(self.project_id))
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instances(
                self.project_id, fake_compute.FAKE_INSTANCE_ZONE))

    def test_get_instance_group_instances_by_zone(self):
        """Test get instances group instances by zone."""
        http_mocks.mock_http_response(
            fake_compute.INSTANCE_GROUP_LIST_INSTANCES)

        results = self.gce_api_client.get_instance_group_instances(
            self.project_id, fake_compute.FAKE_INSTANCE_GROUP,
            zone=fake_compute.FAKE_INSTANCE_ZONE)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_GROUP_ZONE_URLS,
                          list(results))

    def test_get_instance_group_instances_by_region(self):
        """Test get instance group instances by region."""
        http_mocks.mock_http_response(
            fake_compute.REGION_INSTANCE_GROUP_LIST_INSTANCES)

        results = self.gce_api_client.get_instance_group_instances(
            self.project_id, fake_compute.FAKE_INSTANCE_GROUP,
            region=fake_compute.FAKE_INSTANCE_GROUP_REGION)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_GROUP_REGION_URLS,
                          list(results))

    def test_get_instance_group_instances_region_and_zone_raises(self):
      """Verify passing both or neither a region and a zone raises exception."""
      with self.assertRaises(ValueError):
        self.gce_api_client.get_instance_group_instances(
            self.project_id, fake_compute.FAKE_INSTANCE_GROUP,
            zone=fake_compute.FAKE_INSTANCE_ZONE,
            region=fake_compute.FAKE_INSTANCE_GROUP_REGION)

      with self.assertRaises(ValueError):
        self.gce_api_client.get_instance_group_instances(
            self.project_id, fake_compute.FAKE_INSTANCE_GROUP)

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_instance_group_instances_errors(self, name, response, status,
                                                 expected_exception):
        """Verify error conditions for get instance group instances."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instance_group_instances(
                self.project_id, fake_compute.FAKE_INSTANCE_GROUP,
                zone=fake_compute.FAKE_INSTANCE_ZONE))

        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instance_group_instances(
                self.project_id, fake_compute.FAKE_INSTANCE_GROUP,
                region=fake_compute.FAKE_INSTANCE_GROUP_REGION))

    def test_get_instance_groups(self):
        """Test get instance groups."""
        mock_responses = [
            ({'status': '200'},
             fake_compute.INSTANCE_GROUPS_AGGREGATED_LIST),
            ({'status': '200'},
             fake_compute.INSTANCE_GROUP_LIST_INSTANCES),
            ({'status': '200'},
             fake_compute.REGION_INSTANCE_GROUP_LIST_INSTANCES)
        ]
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gce_api_client.get_instance_groups(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_GROUP_NAMES,
                          [r.get('name') for r in results])
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_GROUP_URLS,
                          [r.get('instance_urls') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_instance_groups_errors(self, name, response, status,
                                        expected_exception):
        """Verify error conditions for get instance groups."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instance_groups(self.project_id))

    def test_get_instance_templates(self):
        """Test get instance templates."""
        http_mocks.mock_http_response(fake_compute.INSTANCE_TEMPLATES_LIST)

        results = self.gce_api_client.get_instance_templates(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_TEMPLATE_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_instance_templatess_errors(self, name, response, status,
                                            expected_exception):
        """Verify error conditions for get instance templates."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instance_templates(self.project_id))

    def test_get_instance_group_managers(self):
        """Test get instance templates."""
        http_mocks.mock_http_response(
            fake_compute.INSTANCE_GROUP_MANAGERS_AGGREGATED_LIST)

        results = self.gce_api_client.get_instance_group_managers(
            self.project_id)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_GROUP_MANAGER_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_instance_group_managers_errors(self, name, response, status,
                                            expected_exception):
        """Verify error conditions for get instance templates."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.get_instance_group_managers(self.project_id)


if __name__ == '__main__':
    unittest.main()
