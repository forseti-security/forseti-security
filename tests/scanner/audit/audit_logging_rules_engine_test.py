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

"""Tests the AuditLoggingRulesEngine."""

import unittest
import mock
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path

from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.iam_policy import IamAuditConfig
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.audit import audit_logging_rules_engine as alre
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError


class AuditLoggingRulesEngineTest(ForsetiTestCase):
    """Tests for the AuditLoggingRulesEngine."""

    def setUp(self):
        """Set up GCP resources for tests."""
        self.alre = alre
        self.alre.LOGGER = mock.MagicMock()
        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.folder_56 = Folder(
            '56',
            display_name='Folder 56',
            full_name='folder/56',
            data='fake_folder_data456456')

        self.proj_1 = Project(
            'proj-1',
            project_number=11223344,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/proj-1/',
            data='fake_project_data_2341')

        self.proj_2 = Project(
            'proj-2',
            project_number=223344,
            display_name='My project 2',
            parent=self.folder_56,
            full_name='organization/234/folder/56/project/proj-2/',
            data='fake_project_data_4562')

        self.proj_3 = Project(
            'project-3',
            project_number=33445566,
            display_name='My project 3',
            parent=self.org_234,
            full_name='organization/234/project/proj-3/',
            data='fake_project_data_1233')

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Tests that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(
            __file__, 'audit_logging_test_valid_rules.yaml')
        rules_engine = alre.AuditLoggingRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 5 difference resources.
        self.assertEqual(5, len(rules_engine.rule_book.resource_rules_map))
        rule_resources = []
        for resource in rules_engine.rule_book.resource_rules_map:
            rule_resources.append(resource.name)
        expected_rule_resources = [
            'folders/56', 'projects/*', 'projects/proj-1', 'projects/proj-2',
            'projects/proj-3']
        self.assertEqual(expected_rule_resources, sorted(rule_resources))

    def test_build_rule_book_invalid_mode_fails(self):
        """Tests that a rule with an inavlid mode cannot be created."""
        rules_local_path = get_datafile_path(
            __file__, 'audit_logging_test_invalid_rules.yaml')
        rules_engine = alre.AuditLoggingRulesEngine(
            rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()

    def test_project_with_no_violations(self):
        """Tests that no violations are produced for a correct project."""
        rules_local_path = get_datafile_path(
            __file__, 'audit_logging_test_valid_rules.yaml')
        rules_engine = alre.AuditLoggingRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 5 difference resources.
        self.assertEqual(5, len(rules_engine.rule_book.resource_rules_map))

        # proj-1 needs ADMIN_READ for allServices, and all three log types
        # for compute and cloudsql.
        service_configs = {
            'allServices': {
                'ADMIN_READ': set(),
                'DATA_READ': set(),
            },
            'compute.googleapis.com': {
                'DATA_WRITE': set(['user:user1@org.com']),
            },
            'cloudsql.googleapis.com': {
                'DATA_WRITE': set(),
            },
            'logging.googleapis.com': {
                'DATA_READ': set(['user:log-reader@org.com']),
            }
        }
        actual_violations = rules_engine.find_violations(
            self.proj_1, IamAuditConfig(service_configs))
        self.assertEqual(set(), actual_violations)

    def test_project_with_missing_log_configs(self):
        """Tests rules catch missing log types."""
        rules_local_path = get_datafile_path(
            __file__, 'audit_logging_test_valid_rules.yaml')
        rules_engine = alre.AuditLoggingRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 5 difference resources.
        self.assertEqual(5, len(rules_engine.rule_book.resource_rules_map))

        # proj-2 requires all 3 log types for compute, and ADMIN_READ+DATA_WRITE
        # for everything.
        service_configs = {
            'allServices': {
                'ADMIN_READ': set(),
            },
            'compute.googleapis.com': {
                'DATA_WRITE': set(),
            },
            'cloudsql.googleapis.com': {
                'DATA_WRITE': set(),
            }
        }
        actual_violations = rules_engine.find_violations(
            self.proj_2, IamAuditConfig(service_configs))
        expected_violations = set([
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='proj-2',
                resource_name='My project 2',
                full_name='organization/234/folder/56/project/proj-2/',
                rule_name='Require DATA_WRITE logging in folder 56',
                rule_index=1,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='allServices',
                log_type='DATA_WRITE',
                unexpected_exemptions=None,
                resource_data='fake_project_data_4562'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='proj-2',
                resource_name='My project 2',
                full_name='organization/234/folder/56/project/proj-2/',
                rule_name='Require all logging for compute, with exemptions.',
                rule_index=2,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='compute.googleapis.com',
                log_type='DATA_READ',
                unexpected_exemptions=None,
                resource_data='fake_project_data_4562'),
        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_project_with_unexpected_exemptions(self):
        """Tests rules catch unexpected exemptions."""
        rules_local_path = get_datafile_path(
            __file__, 'audit_logging_test_valid_rules.yaml')
        rules_engine = alre.AuditLoggingRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 5 difference resources.
        self.assertEqual(5, len(rules_engine.rule_book.resource_rules_map))

        # proj-3 needs ADMIN_READ for allServices (user1 & 3 exempted), and all
        # three log types for cloudsql (no exemptions).
        service_configs = {
            'allServices': {
                'ADMIN_READ': set(['user:user1@org.com', 'user:user2@org.com']),
                'DATA_READ': set(['user:user1@org.com']),
            },
            'compute.googleapis.com': {
                'DATA_WRITE': set(['user:data-writer@org.com']),
            },
            'cloudsql.googleapis.com': {
                'ADMIN_READ': set(),
                'DATA_READ': set(['user:user1@org.com', 'user:user2@org.com']),
                'DATA_WRITE': set(),
            },
        }
        actual_violations = rules_engine.find_violations(
            self.proj_3, IamAuditConfig(service_configs))
        expected_violations = set([
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require AUDIT_READ on all services, with exmptions.',
                rule_index=0,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='allServices',
                log_type='ADMIN_READ',
                unexpected_exemptions=('user:user2@org.com',),
                resource_data='fake_project_data_1233'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require all logging for cloudsql.',
                rule_index=3,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='cloudsql.googleapis.com',
                log_type='DATA_READ',
                unexpected_exemptions=('user:user1@org.com',
                                       'user:user2@org.com'),
                resource_data='fake_project_data_1233'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require all logging for cloudsql.',
                rule_index=3,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='allServices',
                log_type='DATA_READ',
                unexpected_exemptions=('user:user1@org.com',),
                resource_data='fake_project_data_1233'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require all logging for cloudsql.',
                rule_index=3,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='allServices',
                log_type='ADMIN_READ',
                unexpected_exemptions=('user:user1@org.com',
                                       'user:user2@org.com'),
                resource_data='fake_project_data_1233'),
        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_project_with_no_configs(self):
        """Tests rules catch missing log types if a project has no config."""
        rules_local_path = get_datafile_path(
            __file__, 'audit_logging_test_valid_rules.yaml')
        rules_engine = alre.AuditLoggingRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 5 difference resources.
        self.assertEqual(5, len(rules_engine.rule_book.resource_rules_map))

        # proj-3 needs ADMIN_READ for allServices (user1 & 3 exempted), and all
        # three log types for cloudsql (no exemptions).
        service_configs = {}
        actual_violations = rules_engine.find_violations(
            self.proj_3, IamAuditConfig(service_configs))
        expected_violations = set([
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require AUDIT_READ on all services, with exmptions.',
                rule_index=0,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='allServices',
                log_type='ADMIN_READ',
                unexpected_exemptions=None,
                resource_data='fake_project_data_1233'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require all logging for cloudsql.',
                rule_index=3,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='cloudsql.googleapis.com',
                log_type='ADMIN_READ',
                unexpected_exemptions=None,
                resource_data='fake_project_data_1233'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require all logging for cloudsql.',
                rule_index=3,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='cloudsql.googleapis.com',
                log_type='DATA_READ',
                unexpected_exemptions=None,
                resource_data='fake_project_data_1233'),
            alre.Rule.RuleViolation(
                resource_type='project',
                resource_id='project-3',
                resource_name='My project 3',
                full_name='organization/234/project/proj-3/',
                rule_name='Require all logging for cloudsql.',
                rule_index=3,
                violation_type='AUDIT_LOGGING_VIOLATION',
                service='cloudsql.googleapis.com',
                log_type='DATA_WRITE',
                unexpected_exemptions=None,
                resource_data='fake_project_data_1233'),
        ])
        self.assertEqual(expected_violations, actual_violations)


if __name__ == '__main__':
    unittest.main()
