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

"""Tests the EnabledApisRulesEngine."""

import unittest
import mock
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path

from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.audit import enabled_apis_rules_engine as eare
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError


class EnabledApisRulesEngineTest(ForsetiTestCase):
    """Tests for the EnabledApisRulesEngine."""

    def setUp(self):
        """Set up GCP resources for tests."""
        self.rule_index = 0
        self.eare = eare
        self.eare.LOGGER = mock.MagicMock()

        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.folder_123 = Folder(
            '123',
            display_name='Folder 123',
            full_name='folder/123',
            data='fake_folder_data456456')

        self.folder_456 = Folder(
            '456',
            display_name='Folder 456',
            parent=self.org_234,
            full_name='organization/234/folder/456/',
            data='fake_folder_data456456')

        self.proj_1 = Project(
            'project-1',
            project_number=11223344,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/project-1/',
            data='fake_project_data_2341')

        self.proj_2 = Project(
            'project-2',
            project_number=223344,
            display_name='My project 2',
            parent=self.folder_456,
            full_name='organization/234/folder/456/project/project-2/',
            data='fake_project_data_4562')

        self.proj_3 = Project(
            'project-3',
            project_number=33445566,
            display_name='My project 2',
            parent=self.folder_123,
            full_name='folder/123/project/project-3/',
            data='fake_project_data_1233')

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(
            __file__, 'enabled_apis_test_rules_1.yaml')
        rules_engine = eare.EnabledApisRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 4 difference resources.
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_overlapping_resources_works(self):
        """Test a RuleBook with multiple rules on a single resource."""
        rules_local_path = get_datafile_path(
            __file__, 'enabled_apis_test_rules_2.yaml')
        rules_engine = eare.EnabledApisRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        # Creates rules for 2 difference resources.
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_invalid_mode_fails(self):
        """Test that a rule with an inavlid mode cannot be created."""
        rules_local_path = get_datafile_path(__file__,
                                             'enabled_apis_test_rules_3.yaml')
        rules_engine = eare.EnabledApisRulesEngine(
            rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()

    def test_find_whitelist_violation(self):
        """Test whitelist rules."""
        rules_local_path = get_datafile_path(
            __file__, 'enabled_apis_test_rules_1.yaml')
        rules_engine = eare.EnabledApisRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

        # Everything is allowed.
        violations = rules_engine.find_violations(
            self.proj_3,
            ['foo.googleapis.com', 'bar.googleapis.com', 'baz.googleapis.com'])
        self.assertEquals(0, len(list(violations)))

        # Non-whitelisted APIs.
        violations = list(rules_engine.find_violations(
            self.proj_3,
            ['alpha.googleapis.com', 'bar.googleapis.com', 'other-api.com']))
        self.assertEquals(1, len(violations))
        self.assertEquals(eare.VIOLATION_TYPE, violations[0].violation_type)
        self.assertEquals(('alpha.googleapis.com', 'other-api.com'),
                          violations[0].apis)

        # API is whitelisted for Organization, but not globally (wildcard).
        violations = list(rules_engine.find_violations(
            self.proj_1, ['qux.googleapis.com']))
        self.assertEquals(1, len(violations))
        self.assertEquals(eare.VIOLATION_TYPE, violations[0].violation_type)
        self.assertEquals(('qux.googleapis.com',), violations[0].apis)

    def test_find_blacklist_violation(self):
        """Test blacklist rules."""
        rules_local_path = get_datafile_path(__file__,
                                             'enabled_apis_test_rules_1.yaml')
        rules_engine = eare.EnabledApisRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(4, len(rules_engine.rule_book.resource_rules_map))

        # Everything is allowed.
        violations = rules_engine.find_violations(
            self.proj_1, ['foo.googleapis.com', 'baz.googleapis.com'])
        self.assertEquals(0, len(list(violations)))

        # Blacklisted APIs.
        violations = list(rules_engine.find_violations(
            self.proj_1,
            ['foo.googleapis.com', 'bar.googleapis.com', 'baz.googleapis.com']))
        self.assertEquals(1, len(violations))
        self.assertEquals(eare.VIOLATION_TYPE, violations[0].violation_type)
        self.assertEquals(('bar.googleapis.com',), violations[0].apis)

    def test_find_required_violation(self):
        """Test required api rules."""
        rules_local_path = get_datafile_path(__file__,
                                             'enabled_apis_test_rules_2.yaml')
        rules_engine = eare.EnabledApisRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))

        # Required API is included.
        violations = rules_engine.find_violations(
            self.proj_3, ['foo.googleapis.com', 'bar.googleapis.com'])
        self.assertEquals(0, len(list(violations)))

        # Required API is missing.
        violations = list(rules_engine.find_violations(
            self.proj_3, ['foo.googleapis.com']))
        self.assertEquals(1, len(violations))
        self.assertEquals(eare.VIOLATION_TYPE, violations[0].violation_type)
        self.assertEquals(('bar.googleapis.com',), violations[0].apis)

        # Required rule doesn't apply to project.
        violations = rules_engine.find_violations(
            self.proj_2, ['foo.googleapis.com'])
        self.assertEquals(0, len(list(violations)))


if __name__ == '__main__':
    unittest.main()
