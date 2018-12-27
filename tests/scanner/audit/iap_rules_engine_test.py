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

"""Tests the IapRulesEngine."""

import copy
import itertools
import mock
import unittest
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import backend_service
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import iap_rules_engine as ire
from google.cloud.forseti.scanner.scanners import iap_scanner
from tests.unittest_utils import get_datafile_path
from tests.scanner.audit.data import test_iap_rules


class IapRulesEngineTest(ForsetiTestCase):
    """Tests for the IapRulesEngine."""

    def setUp(self):
        """Set up."""
        self.maxDiff = None
        self.fake_timestamp = '12345'
        self.org789 = Organization('778899', display_name='My org')
        self.project1 = Project(
            'my-project-1', 12345,
            display_name='My project 1',
            parent=self.org789)
        self.project2 = Project('my-project-2', 12346,
            display_name='My project 2')

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__, 'iap_test_rules_1.yaml')
        rules_engine = ire.IapRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_from_local_json_file_works(self):
        """Test that a RuleBook is built correctly with a json file."""
        rules_local_path = get_datafile_path(__file__, 'iap_test_rules_1.json')
        rules_engine = ire.IapRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        self.assertEqual(2, len(rules_engine.rule_book.resource_rules_map))

    @mock.patch.object(file_loader,
                       '_read_file_from_gcs', autospec=True)
    def test_build_rule_book_from_gcs_works(self, mock_load_rules_from_gcs):
        """Test that a RuleBook is built correctly with a mocked gcs file.

        Setup:
            * Create a mocked GCS object from a test yaml file.
            * Get the yaml file content.

        Expected results:
            There are 4 resources that have rules, in the rule book.
        """
        bucket_name = 'bucket-name'
        rules_path = 'input/test_rules_1.yaml'
        full_rules_path = 'gs://{}/{}'.format(bucket_name, rules_path)
        rules_engine = ire.IapRulesEngine(rules_file_path=full_rules_path)

        # Read in the rules file
        file_content = None
        with open(get_datafile_path(__file__, 'iap_test_rules_1.yaml'),
                  'r') as rules_local_file:
            try:
                file_content = yaml.safe_load(rules_local_file)
            except yaml.YAMLError:
                raise

        mock_load_rules_from_gcs.return_value = file_content

        rules_engine.build_rule_book({})
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_resource_type_fails(self):
        """Test that a rule without a resource type cannot be created."""
        rules_local_path = get_datafile_path(__file__, 'iap_test_rules_2.yaml')
        rules_engine = ire.IapRulesEngine(rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book({})

    def test_add_single_rule_builds_correct_map(self):
        """Test that adding a single rule builds the correct map."""
        rule_book = ire.IapRuleBook(
            {}, test_iap_rules.RULES1, self.fake_timestamp)
        actual_rules = rule_book.resource_rules_map

        rule = ire.Rule('my rule', 0, [], [], '^.*$')
        expected_org_rules = ire.ResourceRules(self.org789,
                                               rules=set([rule]),
                                               applies_to='self_and_children')
        expected_proj1_rules = ire.ResourceRules(self.project1,
                                                 rules=set([rule]),
                                                 applies_to='self')
        expected_proj2_rules = ire.ResourceRules(self.project2,
                                                 rules=set([rule]),
                                                 applies_to='self')
        expected_rules = {
            (self.org789, 'self_and_children'): expected_org_rules,
            (self.project1, 'self'): expected_proj1_rules,
            (self.project2, 'self'): expected_proj2_rules
        }
        self.assertEqual(expected_rules, actual_rules)

    def test_no_violations(self):
        rule = ire.Rule('my rule', 0, [], [], '^.*$')
        resource_rule = ire.ResourceRules(self.org789,
                                          rules=set([rule]),
                                          applies_to='self_and_children')
        service = backend_service.BackendService(
            project_id=self.project1.id,
            name='bs1')
        iap_resource = iap_scanner.IapResource(
            project_full_name='',
            backend_service=service,
            alternate_services=set(),
            direct_access_sources=set(),
            iap_enabled=True)
        results = list(resource_rule.find_mismatches(service,
                                                     iap_resource))
        self.assertEquals([], results)

    def test_enabled_violation(self):
        rule = ire.Rule('my rule', 0, [], [], '^True')
        resource_rule = ire.ResourceRules(self.org789,
                                          rules=set([rule]),
                                          applies_to='self_and_children')
        service = backend_service.BackendService(
            full_name='fake_full_name111',
            project_id=self.project1.id,
            name='bs1')
        iap_resource = iap_scanner.IapResource(
            project_full_name='',
            backend_service=service,
            alternate_services=set(),
            direct_access_sources=set(),
            iap_enabled=False)
        results = list(resource_rule.find_mismatches(service,
                                                     iap_resource))
        expected_violations = [
            ire.RuleViolation(
                resource_type=resource_mod.ResourceType.BACKEND_SERVICE,
                resource_name='bs1',
                resource_id=service.resource_id,
                full_name='fake_full_name111',
                rule_name=rule.rule_name,
                rule_index=rule.rule_index,
                violation_type='IAP_VIOLATION',
                alternate_services_violations=[],
                direct_access_sources_violations=[],
                iap_enabled_violation=True,
                resource_data='{"full_name": "fake_full_name111", "id": "None", "name": "bs1"}'),
        ]
        self.assertEquals(expected_violations, results)

    def test_alternate_service_violation(self):
        rule = ire.Rule('my rule', 0, [], [], '^True')
        resource_rule = ire.ResourceRules(self.org789,
                                          rules=set([rule]),
                                          applies_to='self_and_children')
        service = backend_service.BackendService(
            full_name='fake_full_name111',
            project_id=self.project1.id,
            name='bs1')
        alternate_service = backend_service.Key.from_args(
            project_id=self.project1.id,
            name='bs2')
        iap_resource = iap_scanner.IapResource(
            project_full_name='',
            backend_service=service,
            alternate_services=set([alternate_service]),
            direct_access_sources=set(),
            iap_enabled=True)
        results = list(resource_rule.find_mismatches(service,
                                                     iap_resource))
        expected_violations = [
            ire.RuleViolation(
                resource_type=resource_mod.ResourceType.BACKEND_SERVICE,
                resource_name='bs1',
                resource_id=service.resource_id,
                full_name='fake_full_name111',
                rule_name=rule.rule_name,
                rule_index=rule.rule_index,
                violation_type='IAP_VIOLATION',
                alternate_services_violations=[alternate_service],
                direct_access_sources_violations=[],
                iap_enabled_violation=False,
                resource_data='{"full_name": "fake_full_name111", "id": "None", "name": "bs1"}'),
        ]
        self.assertEquals(expected_violations, results)

    def test_direct_access_violation(self):
        rule = ire.Rule('my rule', 0, [], [], '^.*')
        resource_rule = ire.ResourceRules(self.org789,
                                          rules=set([rule]),
                                          applies_to='self_and_children')
        direct_source = 'some-tag'
        service = backend_service.BackendService(
            full_name='fake_full_name111',
            project_id=self.project1.id,
            name='bs1')
        iap_resource = iap_scanner.IapResource(
            project_full_name='',
            backend_service=service,
            alternate_services=set(),
            direct_access_sources=set([direct_source]),
            iap_enabled=True)
        results = list(resource_rule.find_mismatches(service,
                                                     iap_resource))
        expected_violations = [
            ire.RuleViolation(
                resource_type=resource_mod.ResourceType.BACKEND_SERVICE,
                resource_name='bs1',
                resource_id=service.resource_id,
                full_name='fake_full_name111',
                rule_name=rule.rule_name,
                rule_index=rule.rule_index,
                violation_type='IAP_VIOLATION',
                alternate_services_violations=[],
                direct_access_sources_violations=[direct_source],
                iap_enabled_violation=False,
                resource_data='{"full_name": "fake_full_name111", "id": "None", "name": "bs1"}'),
        ]
        self.assertEquals(expected_violations, results)

    def test_violations_iap_disabled(self):
        """If IAP is disabled, don't report other violations."""
        rule = ire.Rule('my rule', 0, [], [], '^.*')
        resource_rule = ire.ResourceRules(self.org789,
                                          rules=set([rule]),
                                          applies_to='self_and_children')
        service = backend_service.BackendService(
            full_name='fake_full_name111',
            project_id=self.project1.id,
            name='bs1')
        alternate_service = backend_service.Key.from_args(
            project_id=self.project1.id,
            name='bs2')
        iap_resource = iap_scanner.IapResource(
            project_full_name='',
            backend_service=service,
            alternate_services=set([alternate_service]),
            direct_access_sources=set(['some-tag']),
            iap_enabled=False)
        results = list(resource_rule.find_mismatches(service,
                                                     iap_resource))
        expected_violations = []
        self.assertEquals(expected_violations, results)


if __name__ == '__main__':
    unittest.main()
