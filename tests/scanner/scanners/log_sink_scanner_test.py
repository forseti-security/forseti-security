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
"""Tests for LogSinkScanner."""

import json
import unittest
import mock

from tests.scanner.test_data import fake_log_sink_scanner_data as flsd
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import log_sink_scanner



def _mock_gcp_resource_iter(_, resource_type):
    """Creates a list of GCP resource mocks retrieved by the scanner."""
    resources = []
    if resource_type == 'sink':
        for resource in flsd.LOG_SINK_RESOURCES:
            sink = mock.MagicMock()
            # For testing the scanner, only look at the sink name.
            sink.data = json.dumps({'name': resource['sink_name']})
            sink.parent_type_name = resource['parent']
            sink.parent = mock.MagicMock()
            resources.append(sink)
    else:
        for full_name in flsd.GCP_RESOURCES[resource_type]:
            parent = mock.MagicMock()
            name = full_name.split('/')[-2]
            parent.name = name
            parent.type_name = resource_type + '/' + name
            parent.full_name = full_name
            resources.append(parent)
    return resources


class LogSinkScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.log_sink_scanner.'
        'log_sink_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        self.scanner = log_sink_scanner.LogSinkScanner(
            {}, {}, mock.MagicMock(), '', '', '')

    def test_retrieve(self):
        """Tests _retrieve gets all log sinks and parent resources."""
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.side_effect = _mock_gcp_resource_iter
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        log_sink_data = self.scanner._retrieve()

        expected_parents = [
            'organization/234/',
            'organization/234/billing_account/ABCD-1234/',
            'organization/234/folder/56/',
            'organization/234/project/proj-1/',
            'organization/234/folder/56/project/proj-2/',
            'organization/234/project/proj-3/',
        ]
        expected_log_sinks = [
            ['org_sink_1', 'org_sink_2'],
            ['billing_sink'],
            ['folder_sink'],
            [],
            ['p2_sink_1', 'p2_sink_2'],
            ['p3_sink'],
        ]

        self.assertEqual(len(expected_log_sinks), len(log_sink_data))

        for i in range(len(expected_log_sinks)):
            actual_parent, actual_log_sink_configs = log_sink_data[i]
            self.assertEqual(expected_parents[i], actual_parent.full_name)
            actual_log_sinks = [sink.id for sink in actual_log_sink_configs]
            self.assertEqual(expected_log_sinks[i], actual_log_sinks)

    def test_find_violations(self):
        """Tests _find_violations passes log sink configs to the rule engine."""
        log_sink_data = [
            ('resource-1', 'resource-1-log-sinks'),
            ('resource-2', 'resource-2-log-sinks'),
            ('resource-3', 'resource-3-log-sinks')
        ]

        self.scanner.rules_engine.find_violations.side_effect = [
            ['viol-1', 'viol-2'], [], ['viol-3']]

        violations = self.scanner._find_violations(log_sink_data)

        self.scanner.rules_engine.find_violations.assert_has_calls(
            [mock.call(parent, data) for parent, data in log_sink_data])

        self.assertEquals(['viol-1', 'viol-2', 'viol-3'], violations)

    @mock.patch.object(
        log_sink_scanner.LogSinkScanner,
        '_output_results_to_db', autospec=True)
    def test_output_results(self, mock_output_results_to_db):
        """Tests _output_results() flattens results & writes them to db."""
        self.scanner._output_results(flsd.LOG_SINK_VIOLATIONS)

        mock_output_results_to_db.assert_called_once_with(
            self.scanner, flsd.FLATTENED_LOG_SINK_VIOLATIONS)


if __name__ == '__main__':
    unittest.main()
