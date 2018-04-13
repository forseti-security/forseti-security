# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Enabled APIs Scanner Test"""
import json
import unittest
import mock

from tests.unittest_utils import ForsetiTestCase
from tests.scanner.test_data import fake_enabled_apis_scanner_data as feasd
from google.cloud.forseti.scanner.scanners import enabled_apis_scanner


def create_list_of_mock_enabled_api_resources():
    """Creates a list of enabled_apis resource mocks received by the scanner."""
    resources = []
    for data in feasd.ENABLED_APIS_RESOURCES:
        apis = mock.MagicMock()
        apis.data = json.dumps(data['enabled_apis'])
        apis.parent = mock.MagicMock()
        apis.parent.name = data['project_name']
        apis.parent.full_name = data['project_full_name']
        resources.append(apis)

    return resources

class EnabledApisScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.enabled_apis_scanner.'
        'enabled_apis_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        self.scanner = enabled_apis_scanner.EnabledApisScanner(
            {}, {}, mock.MagicMock(), '', '', '')

    def test_retrieve(self):
        """Tests the _retrieve method gets all projects' enabled APIs."""
        enabled_apis_resources = create_list_of_mock_enabled_api_resources()
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = enabled_apis_resources
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        enabled_apis_data = self.scanner._retrieve()

        expected_projects = [
            'projects/proj-1', 'projects/proj-2', 'projects/proj-3']
        expected_enabled_apis = [
          ['compute.googleapis.com', 'logging.googleapis.com',
           'monitoring.googleapis.com', 'storage.googleapis.com'],
          ['compute.googleapis.com', 'logging.googleapis.com',
           'storage.googleapis.com'],
          ['logging.googleapis.com', 'monitoring.googleapis.com',
           'pubsub.googleapis.com', 'storage.googleapis.com']]

        self.assertEqual(3, len(enabled_apis_data))

        for i in xrange(3):
          actual_project, actual_enabled_apis = enabled_apis_data[i]
          self.assertEqual(expected_projects[i], actual_project.name)
          self.assertEqual(expected_enabled_apis[i], actual_enabled_apis)

    def test_find_violations(self):
        """Tests _find_violations passes enabled API data to the rule engine."""
        enabled_apis_data = [
            ('proj-1', 'project-1-api-data'),
            ('proj-2', 'project-2-api-data'),
            ('proj-3', 'project-3-api-data')
        ]

        self.scanner.rules_engine.find_violations.side_effect = [
            ['viol-1', 'viol-2'], [], ['viol-3']]

        violations = self.scanner._find_violations(enabled_apis_data)

        self.scanner.rules_engine.find_violations.assert_has_calls(
            [mock.call(proj, data) for proj, data in enabled_apis_data])

        self.assertEquals(['viol-1', 'viol-2', 'viol-3'], violations)

    @mock.patch.object(
        enabled_apis_scanner.EnabledApisScanner,
        '_output_results_to_db', autospec=True)
    def test_output_results(
        self, mock_output_results_to_db):
        """Tests _output_results() flattens results & writes them to db."""
        self.scanner._output_results(feasd.ENABLED_APIS_VIOLATIONS)

        mock_output_results_to_db.assert_called_once_with(
            self.scanner, feasd.FLATTENED_ENABLED_APIS_VIOLATIONS)


if __name__ == '__main__':
    unittest.main()
