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
import json
import unittest
import uuid
import mock
import parameterized
import google.auth
from google.oauth2 import credentials

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_compute_responses as fake_compute
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import errors as api_errors

ERROR_TEST_CASES = [
    ('api_not_enabled', fake_compute.API_NOT_ENABLED, '403',
     api_errors.ApiNotEnabledError),
    ('access_denied', fake_compute.ACCESS_DENIED, '403',
     api_errors.ApiExecutionError),
]

# Test create, patch, update and delete operations.
CUD_TEST_CASES = [
    ('delete', 'delete'),
    ('insert', 'insert'),
    ('patch', 'patch'),
    ('update', 'update'),
]


class ComputeTest(unittest_utils.ForsetiTestCase):
    """Test the Compute client."""

    @classmethod
    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def setUpClass(cls, mock_google_credential):
        """Set up."""
        fake_global_configs = {
            'compute': {'max_calls': 18, 'period': 1}}
        cls.gce_api_client = compute.ComputeClient(
            global_configs=fake_global_configs)
        cls.project_id = fake_compute.FAKE_PROJECT_ID

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
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

    def test_get_disks(self):
        """Test get disks."""
        http_mocks.mock_http_response(
            fake_compute.DISKS_AGGREGATED_LIST)

        results = self.gce_api_client.get_disks(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_DISKS_SELFLINKS,
                          [r.get('selfLink') for r in results])

    def test_get_disks_by_zone(self):
        """Test get disks rules by zone."""
        http_mocks.mock_http_response(fake_compute.DISKS_LIST)

        results = self.gce_api_client.get_disks(
            self.project_id, fake_compute.FAKE_DISK_ZONE)
        self.assertEquals(fake_compute.EXPECTED_DISKS_SELFLINKS,
                          [r.get('selfLink') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_disks_errors(self, name, response, status,
                              expected_exception):
        """Verify error conditions for get disks."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_disks(self.project_id))
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_disks(
                self.project_id, fake_compute.FAKE_DISK_ZONE))

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

    @parameterized.parameterized.expand(CUD_TEST_CASES)
    def test_cud_firewall_rule(self, name, verb):
        """Test create/patch/update/delete firewall rule."""
        mock_response = fake_compute.PENDING_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        http_mocks.mock_http_response(mock_response)
        method = getattr(self.gce_api_client,
                         '{}_firewall_rule'.format(verb))

        results = method(self.project_id, rule=fake_compute.FAKE_FIREWALL_RULE,
                         uuid=uuid.uuid4())
        self.assertDictEqual(json.loads(mock_response), results)

    @parameterized.parameterized.expand(CUD_TEST_CASES)
    def test_cud_firewall_rule_read_only(self, name, verb):
        """Test create/patch/update/delete firewall rule."""
        with mock.patch.object(self.gce_api_client.repository.firewalls,
                               'read_only', return_value=True):
            method = getattr(self.gce_api_client,
                             '{}_firewall_rule'.format(verb))
            results = method(self.project_id,
                             rule=fake_compute.FAKE_FIREWALL_RULE)
            expected_result = {
                'targetLink': (
                    'https://www.googleapis.com/compute/v1/projects/'
                    'project1/global/firewalls/fake-firewall'),
                'operationType': verb,
                'name': 'fake-firewall',
                'status': 'DONE',
                'progress': 100,
            }
            self.assertDictEqual(expected_result, results)

    @parameterized.parameterized.expand(CUD_TEST_CASES)
    def test_cud_firewall_rule_blocking(self, name, verb):
        """Test create/patch/update/delete firewall blocks until complete."""
        mock_pending = fake_compute.PENDING_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        mock_finished = fake_compute.FINISHED_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        mock_responses = [
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_finished)]
        http_mocks.mock_http_response_sequence(mock_responses)

        # Don't wait for API to complete in test.
        with mock.patch.object(self.gce_api_client,
                               'ESTIMATED_API_COMPLETION_IN_SEC',
                               return_value=0):
            method = getattr(self.gce_api_client,
                             '{}_firewall_rule'.format(verb))
            results = method(self.project_id,
                             rule=fake_compute.FAKE_FIREWALL_RULE,
                             blocking=True)
        self.assertDictEqual(json.loads(mock_finished), results)

    @parameterized.parameterized.expand(CUD_TEST_CASES)
    def test_cud_firewall_rule_timeout(self, name, verb):
        """Test create/patch/update/delete firewall rule times out."""
        mock_pending = fake_compute.PENDING_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        mock_finished = fake_compute.FINISHED_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        mock_responses = [
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_finished)]
        http_mocks.mock_http_response_sequence(mock_responses)

        # Set initial wait to longer than the timeout
        with mock.patch.object(self.gce_api_client,
                               'ESTIMATED_API_COMPLETION_IN_SEC',
                               return_value=2):
            with self.assertRaises(api_errors.OperationTimeoutError) as e:
                method = getattr(self.gce_api_client,
                                 '{}_firewall_rule'.format(verb))
                results = method(self.project_id,
                                 rule=fake_compute.FAKE_FIREWALL_RULE,
                                 blocking=True,
                                 timeout=1)
        self.assertDictEqual(json.loads(mock_pending), e.exception.operation)

    @parameterized.parameterized.expand(CUD_TEST_CASES)
    @mock.patch('google.cloud.forseti.common.gcp_api.compute.LOGGER', autospec=True)
    def test_cud_firewall_rule_retry(self, name, verb, mock_logger):
        """Test create/patch/update/delete firewall rule times out."""
        mock_pending = fake_compute.PENDING_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        mock_finished = fake_compute.FINISHED_OPERATION_TEMPLATE.format(
            verb=verb,
            resource_path='project1/global/firewalls/fake-firewall')
        mock_responses = [
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_pending),
            ({'status': '200'}, mock_finished)]
        http_mocks.mock_http_response_sequence(mock_responses)

        # Set initial wait to longer than the timeout
        with mock.patch.object(self.gce_api_client,
                               'ESTIMATED_API_COMPLETION_IN_SEC',
                               return_value=2):
            method = getattr(self.gce_api_client,
                             '{}_firewall_rule'.format(verb))
            results = method(self.project_id,
                             rule=fake_compute.FAKE_FIREWALL_RULE,
                             blocking=True,
                             timeout=1,
                             retry_count=3)
        self.assertDictEqual(json.loads(mock_finished), results)
        self.assertTrue(mock_logger.warn.called)

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_delete_firewall_rule_errors(self, name, response, status,
                                       expected_exception):
        """Verify error conditions for delete firewall rule."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.delete_firewall_rule(
                self.project_id, rule=fake_compute.FAKE_FIREWALL_RULE)

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_insert_firewall_rule_errors(self, name, response, status,
                                       expected_exception):
        """Verify error conditions for insert firewall rule."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.insert_firewall_rule(
                self.project_id, rule=fake_compute.FAKE_FIREWALL_RULE)

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_update_firewall_rule_errors(self, name, response, status,
                                       expected_exception):
        """Verify error conditions for update firewall rule."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.update_firewall_rule(
                self.project_id, rule=fake_compute.FAKE_FIREWALL_RULE)

    def test_get_global_operation(self):
        """Test get_global_operations."""
        http_mocks.mock_http_response(fake_compute.GLOBAL_OPERATION_RESPONSE)
        results = self.gce_api_client.get_global_operation(
            self.project_id, operation_id=fake_compute.FAKE_OPERATION_ID)
        self.assertEquals(fake_compute.FAKE_OPERATION_ID, results.get('name'))

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_global_operation_errors(self, name, response, status,
                                         expected_exception):
        """Verify error conditions for get global operation."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_global_operation(
                self.project_id, operation_id=fake_compute.FAKE_OPERATION_ID))

    def test_get_image(self):
        """Test get_image."""
        http_mocks.mock_http_response(fake_compute.GET_IMAGE)
        results = self.gce_api_client.get_image(
            self.project_id, image_name=fake_compute.FAKE_IMAGE_NAME)
        self.assertEquals(fake_compute.FAKE_IMAGE_NAME, results.get('name'))

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_image_errors(self, name, response, status, expected_exception):
        """Verify error conditions for get image."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_image(
                self.project_id, image_name=fake_compute.FAKE_IMAGE_NAME))

    def test_get_images(self):
        """Test get images."""
        http_mocks.mock_http_response(fake_compute.LIST_IMAGES)

        results = self.gce_api_client.get_images(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_IMAGE_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_images_errors(self, name, response, status,
                               expected_exception):
        """Verify error conditions for get images."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_images(self.project_id))

    def test_get_quota(self):
        """Test get quota."""
        http_mocks.mock_http_response(fake_compute.GET_PROJECT_RESPONSE)

        results = self.gce_api_client.get_quota(self.project_id,
                                                metric='SNAPSHOTS')
        self.assertEquals(fake_compute.GET_QUOTA_RESPONSE, results)

    def test_get_quota_no_metric(self):
        """Test get quota with no metrics."""
        http_mocks.mock_http_response(fake_compute.GET_PROJECT_RESPONSE)
        with self.assertRaises(KeyError):
            list(self.gce_api_client.get_quota(self.project_id, metric=' '))

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_quota_errors(self, name, response, status, expected_exception):
        """Verify error conditions for get quota."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_quota(self.project_id, metric=None))

    def test_get_firewall_quota(self):
        """Test get firewall quota."""
        http_mocks.mock_http_response(fake_compute.GET_PROJECT_RESPONSE)

        results = self.gce_api_client.get_firewall_quota(self.project_id)
        self.assertEquals(fake_compute.GET_FIREWALL_QUOTA_RESPONSE, results)

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
    def test_get_forwarding_rules_errors(self, name, response, status,
                                         expected_exception):
        """Verify error conditions for get forwarding rules."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_forwarding_rules(self.project_id))
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_forwarding_rules(
                self.project_id, fake_compute.FAKE_FORWARDING_RULE_REGION))

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

    def test_get_instance_group_managers(self):
        """Test get instance group managers."""
        http_mocks.mock_http_response(
            fake_compute.INSTANCE_GROUP_MANAGERS_AGGREGATED_LIST)

        results = self.gce_api_client.get_instance_group_managers(
            self.project_id)
        self.assertEquals(fake_compute.EXPECTED_INSTANCE_GROUP_MANAGER_NAMES,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_instance_group_managers_errors(self, name, response, status,
                                                expected_exception):
        """Verify error conditions for get instance group managers."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.get_instance_group_managers(self.project_id)

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
    def test_get_instance_templates_errors(self, name, response, status,
                                           expected_exception):
        """Verify error conditions for get instance templates."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_instance_templates(self.project_id))

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

    def test_get_networks(self):
        """Test get networks."""
        mock_responses = []
        for page in fake_compute.LIST_NETWORKS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gce_api_client.get_networks(self.project_id)
        self.assertEquals(fake_compute.EXPECTED_NETWORK_NAME,
                          [r.get('name') for r in results])

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_networks_errors(self, name, response, status,
                                 expected_exception):
        """Verify error conditions for get networks."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_networks(self.project_id))

    def test_get_project(self):
        """Test get project."""
        http_mocks.mock_http_response(
            fake_compute.GET_PROJECT_RESPONSE)

        results = self.gce_api_client.get_project(self.project_id)
        self.assertEquals(self.project_id, results.get('name'))

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_project_errors(self, name, response, status,
                                expected_exception):
        """Verify error conditions for get instance templates."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.get_project(self.project_id)

    def test_get_snapshots(self):
        """Test get snapshots."""
        mock_responses = []
        for page in fake_compute.LIST_SNAPSHOTS_RESPONSES:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gce_api_client.get_snapshots(self.project_id)
        self.assertEquals(
            fake_compute.EXPECTED_SNAPSHOTS_LIST_NAMES,
            frozenset([r.get('name') for r in results]))

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_snapshots_errors(self, name, response, status,
                                expected_exception):
        """Verify error conditions for get snapshots templates."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            self.gce_api_client.get_snapshots(self.project_id)

    def test_get_subnetworks(self):
        """Test get subnetworks."""
        mock_responses = []
        for page in fake_compute.SUBNETWORKS_AGGREGATED_LIST:
            mock_responses.append(({'status': '200'}, page))
        http_mocks.mock_http_response_sequence(mock_responses)

        results = self.gce_api_client.get_subnetworks(self.project_id)
        self.assertEquals(
            fake_compute.EXPECTED_SUBNETWORKS_AGGREGATEDLIST_SELFLINKS,
            frozenset([r.get('selfLink') for r in results]))

    def test_get_subnetworks_by_region(self):
        """Test get subnetworks by region."""
        http_mocks.mock_http_response(fake_compute.SUBNETWORKS_LIST)

        results = self.gce_api_client.get_subnetworks(
            self.project_id, fake_compute.FAKE_SUBNETWORK_REGION)
        self.assertEquals(fake_compute.EXPECTED_SUBNETWORKS_LIST_SELFLINKS,
                          frozenset([r.get('selfLink') for r in results]))

    @parameterized.parameterized.expand(ERROR_TEST_CASES)
    def test_get_subnetworks_errors(self, name, response, status,
                                    expected_exception):
        """Verify error conditions for get subnetworks."""
        http_mocks.mock_http_response(response, status)
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_subnetworks(self.project_id))
        with self.assertRaises(expected_exception):
            list(self.gce_api_client.get_subnetworks(
                self.project_id, fake_compute.FAKE_SUBNETWORK_REGION))

    def test_is_api_enabled_true(self):
        """Verify that a positive response from the API returns True."""
        http_mocks.mock_http_response(
            fake_compute.GET_PROJECT_NAME_RESPONSE)
        results = self.gce_api_client.is_api_enabled(self.project_id)
        self.assertTrue(results)

    def test_is_api_enabled_false(self):
        """Verify that a positive response from the API returns True."""
        http_mocks.mock_http_response(fake_compute.API_NOT_ENABLED, '403')
        results = self.gce_api_client.is_api_enabled(self.project_id)
        self.assertFalse(results)

    def test_is_api_enabled_error(self):
        """Verify that a positive response from the API returns True."""
        http_mocks.mock_http_response(fake_compute.ACCESS_DENIED, '403')
        with self.assertRaises(api_errors.ApiExecutionError):
            self.gce_api_client.is_api_enabled(self.project_id)


if __name__ == '__main__':
    unittest.main()
