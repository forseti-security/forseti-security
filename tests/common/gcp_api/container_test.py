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
"""Tests the Google Kubernetes Engine API client."""

import json
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import (
    fake_container_responses as fake_container)
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import container
from google.cloud.forseti.common.gcp_api import errors as api_errors


class ContainerTest(unittest_utils.ForsetiTestCase):
    """Test the Container Client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'container': {'max_calls': 9, 'period': 1}}
        cls.container_client = container.ContainerClient(
            global_configs=fake_global_configs, use_rate_limiter=False)
        cls.project_id = fake_container.FAKE_PROJECT_ID
        cls.zone = fake_container.FAKE_ZONE

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_no_quota(self, mock_google_credential):
        """Verify no rate limiter is used if the configuration is missing."""
        container_client = container.ContainerClient(global_configs={})
        self.assertEqual(None, container_client.repository._rate_limiter)

    def test_get_serverconfig_by_zone(self):
        """Test get KE serverconfig for zone."""
        http_mocks.mock_http_response(
            fake_container.FAKE_GET_SERVERCONFIG_RESPONSE)

        result = self.container_client.get_serverconfig(
            self.project_id, zone=self.zone)

        self.assertEquals(
            json.loads(fake_container.FAKE_GET_SERVERCONFIG_RESPONSE), result)

    def test_get_serverconfig_by_location(self):
        """Test get KE serverconfig for location."""
        http_mocks.mock_http_response(
            fake_container.FAKE_GET_SERVERCONFIG_RESPONSE)

        result = self.container_client.get_serverconfig(
            self.project_id, location=fake_container.FAKE_LOCATION)

        self.assertEquals(
            json.loads(fake_container.FAKE_GET_SERVERCONFIG_RESPONSE), result)

    def test_get_serverconfig_by_location_and_zone(self):
        """Test get KE serverconfig for zone and location."""
        http_mocks.mock_http_response(
            fake_container.FAKE_GET_SERVERCONFIG_RESPONSE)

        result = self.container_client.get_serverconfig(
            self.project_id, zone=self.zone,
            location=fake_container.FAKE_LOCATION)

        self.assertEquals(
            json.loads(fake_container.FAKE_GET_SERVERCONFIG_RESPONSE), result)

    def test_get_serverconfig_missing_location_and_zone(self):
        """Test get_serverconfig raises if missing location and zone."""
        with self.assertRaises(ValueError):
             self.container_client.get_serverconfig(self.project_id)

    def test_get_serverconfig_error(self):
        """Test get_serverconfig raises exception on error."""
        http_mocks.mock_http_response(
            fake_container.INVALID_ARGUMENT_400, '400')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.container_client.get_serverconfig(
                 self.project_id, zone=fake_container.FAKE_BAD_ZONE)


    def test_get_clusters(self):
        """Test get KE clusters."""
        http_mocks.mock_http_response(
            fake_container.FAKE_GET_CLUSTERS_RESPONSE)

        results = self.container_client.get_clusters(self.project_id)
        self.assertEquals(fake_container.EXPECTED_CLUSTER_NAMES,
                          [r.get('name') for r in results])

    def test_get_clusters_error(self):
        """Test get_clusters raises exception on error."""
        http_mocks.mock_http_response(
            fake_container.INVALID_ARGUMENT_400, '400')

        with self.assertRaises(api_errors.ApiExecutionError):
             self.container_client.get_clusters(
                 self.project_id, zone=fake_container.FAKE_BAD_ZONE)


if __name__ == '__main__':
    unittest.main()
