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
"""Tests for AuditLoggingScanner."""

import json
import unittest
import mock

from tests.unittest_utils import ForsetiTestCase
from tests.scanner.test_data import fake_audit_logging_scanner_data as fasd
from google.cloud.forseti.scanner.scanners import audit_logging_scanner


def _create_list_of_mock_iam_resources():
    """Creates a list of iam_policy resource mocks reseived by the scanner"""
    policy_resources = []
    for data in fasd.IAM_POLICY_RESOURCES:
        policy = mock.MagicMock()
        policy.data = json.dumps(data['iam_policy'])
        policy.parent = mock.MagicMock()
        policy.parent.type = data['parent_type']
        policy.parent.name = data['parent_name']
        policy.parent.full_name = data['parent_full_name']
        policy_resources.append(policy)
    return policy_resources

class AuditLoggingScannerTest(ForsetiTestCase):

    @mock.patch(
        'google.cloud.forseti.scanner.scanners.audit_logging_scanner.'
        'audit_logging_rules_engine',
        autospec=True)
    def setUp(self, mock_rules_engine):
        self.scanner = audit_logging_scanner.AuditLoggingScanner(
            {}, {}, mock.MagicMock(), '', '', '')

    def test_retrieve(self):
        """Tests _retrieve gets all projects' merged audit configs."""
        iam_resources = _create_list_of_mock_iam_resources()
        mock_data_access = mock.MagicMock()
        mock_data_access.scanner_iter.return_value = iam_resources
        mock_service_config = mock.MagicMock()
        mock_service_config.model_manager = mock.MagicMock()
        mock_service_config.model_manager.get.return_value = (
            mock.MagicMock(), mock_data_access)
        self.scanner.service_config = mock_service_config

        audit_logging_data = self.scanner._retrieve()

        expected_projects = [
            'organization/234/project/proj-1/',
            'organization/234/folder/56/project/proj-2/',
            'organization/234/project/proj-3/'
        ]
        expected_audit_configs = [
            {
                'allServices': {
                    'ADMIN_READ': set(),
                }
            },
            {
                'allServices': {
                    'ADMIN_READ': set([
                        'user:user1@org.com',
                        'user:user2@org.com',
                        'user:user3@org.com'
                    ]),
                },
                'cloudsql.googleapis.com': {
                    'DATA_READ': set(),
                    'DATA_WRITE': set(),
                },
                'compute.googleapis.com': {
                    'DATA_READ': set(),
                    'DATA_WRITE': set(),
                }
            },
            {
                'allServices': {
                    'ADMIN_READ': set(),
                    'DATA_WRITE': set(),
                },
                'cloudsql.googleapis.com': {
                    'ADMIN_READ': set(['user:user1@org.com']),
                }
            },
        ]

        # _retrieve only returns projects.
        self.assertEqual(3, len(audit_logging_data))

        for i in xrange(3):
            actual_project, actual_audit_configs = audit_logging_data[i]
            self.assertEqual(expected_projects[i], actual_project.full_name)
            self.assertEqual(expected_audit_configs[i],
                             actual_audit_configs.service_configs)

    def test_find_violations(self):
        """Tests _find_violations passes audit configs to the rule engine."""
        audit_logging_data = [
            ('proj-1', 'project-1-iam-audit-config'),
            ('proj-2', 'project-2-iam-audit-config'),
            ('proj-3', 'project-3-iam-audit-config')
        ]

        self.scanner.rules_engine.find_violations.side_effect = [
            ['viol-1', 'viol-2'], [], ['viol-3']]

        violations = self.scanner._find_violations(audit_logging_data)

        self.scanner.rules_engine.find_violations.assert_has_calls(
            [mock.call(proj, data) for proj, data in audit_logging_data])

        self.assertEquals(['viol-1', 'viol-2', 'viol-3'], violations)

    @mock.patch.object(
        audit_logging_scanner.AuditLoggingScanner,
        '_output_results_to_db', autospec=True)
    def test_output_results(self, mock_output_results_to_db):
        """Tests _output_results() flattens results & writes them to db."""
        self.scanner._output_results(fasd.AUDIT_LOGGING_VIOLATIONS)

        mock_output_results_to_db.assert_called_once_with(
            self.scanner, fasd.FLATTENED_AUDIT_LOGGING_VIOLATIONS)


if __name__ == '__main__':
    unittest.main()
