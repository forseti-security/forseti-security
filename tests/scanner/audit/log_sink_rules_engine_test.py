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

"""Tests the LogSinkRulesEngine."""

import unittest
import mock
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path

from google.cloud.forseti.common.gcp_type.billing_account import BillingAccount
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.log_sink import LogSink
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.scanner.audit import log_sink_rules_engine as lsre
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError


class LogSinkRulesEngineTest(ForsetiTestCase):
    """Tests for the LogSinkRulesEngine."""

    def setUp(self):
        """Set up GCP resources for tests."""
        self.lsre = lsre
        self.lsre.LOGGER = mock.MagicMock()

        # Set up resources in the following hierarchy:
        #             +-----> billing_acct_abcd
        #             |
        #             |
        #             +-----------------------> proj-1
        #             |
        #             |
        #     org_234 +-----> folder_56 +-----> proj-2
        #             |
        #             |
        #             +-----------------------> proj-3
        self.org_234 = Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.billing_acct_abcd = BillingAccount(
            'ABCD-1234',
            display_name='Billing Account ABCD',
            full_name='organization/234/billingAccount/ABCD-1234/',
            data='fake_billing_account_data_abcd')

        self.folder_56 = Folder(
            '56',
            display_name='Folder 56',
            full_name='organization/234/folder/56/',
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
            'proj-3',
            project_number=33445566,
            display_name='My project 3',
            parent=self.org_234,
            full_name='organization/234/project/proj-3/',
            data='fake_project_data_1233')

    def get_engine_with_valid_rules(self):
        """Create a rule engine build with a valid rules file."""
        rules_local_path = get_datafile_path(
            __file__, 'log_sink_test_valid_rules.yaml')
        rules_engine = self.lsre.LogSinkRulesEngine(
            rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        return rules_engine

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Tests that a RuleBook is built correctly with a yaml file."""
        rules_engine = self.get_engine_with_valid_rules()
        # Creates 'self' rules for 5 difference resources and 'children' rules
        # for 2.
        self.assertEqual(
            6, len(rules_engine.rule_book.resource_rules_map['self']))
        self.assertEqual(
            2, len(rules_engine.rule_book.resource_rules_map['children']))
        self_rule_resources = []
        for resource in rules_engine.rule_book.resource_rules_map['self']:
            self_rule_resources.append(resource.name)
        expected_rule_resources = [
            'billingAccounts/ABCD-1234', 'folders/56', 'organizations/234',
            'projects/proj-1', 'projects/proj-2', 'projects/proj-3']
        self.assertEqual(expected_rule_resources, sorted(self_rule_resources))

        child_rule_resources = []
        for resource in rules_engine.rule_book.resource_rules_map['children']:
            child_rule_resources.append(resource.name)
        expected_rule_resources = ['folders/56', 'organizations/234']
        self.assertEqual(expected_rule_resources, sorted(child_rule_resources))

    def test_build_rule_book_invalid_applies_to_fails(self):
        """Tests that a rule with invalid applies_to type cannot be created."""
        rules_local_path = get_datafile_path(
            __file__, 'log_sink_test_invalid_rules.yaml')
        rules_engine = self.lsre.LogSinkRulesEngine(
            rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()

    def test_project_with_no_violations(self):
        """Tests that no violations are produced for a correct project."""
        rules_engine = self.get_engine_with_valid_rules()

        # proj-1 needs an Audit Log sink.
        log_sinks = [
            LogSink(
                sink_id='audit_logs_to_bq',
                destination=('bigquery.googleapis.com/projects/my-audit-logs/'
                             'datasets/proj_1_logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.proj_1,
                raw_json='_SINK_1_'
            ),
            LogSink(
                sink_id='compute_logs_saver',
                destination=('bigquery.googleapis.com/projects/proj_1/'
                             'datasets/compute_logs'),
                sink_filter='resource.type="gce_instance"',
                include_children=False,
                writer_identity=('serviceAccount:p12345-67890@'
                                 'gcp-sa-logging.iam.gserviceaccount.com'),
                parent=self.proj_1,
                raw_json='_SINK_2_'
            )
        ]

        actual_violations = rules_engine.find_violations(
            self.proj_1, log_sinks)
        self.assertEqual(set(), actual_violations)

    def test_folder_with_no_violations(self):
        """Tests that no violations are produced for a correct folder."""
        rules_engine = self.get_engine_with_valid_rules()

        # Rules disallow any folder-level LogSinks.
        actual_violations = rules_engine.find_violations(self.folder_56, [])
        self.assertEqual(set(), actual_violations)

    def test_billing_account_with_no_violations(self):
        """Tests that no violations are produced for a correct billing acct."""
        rules_engine = self.get_engine_with_valid_rules()

        log_sinks = [
            LogSink(
                sink_id='billing_logs',
                destination=('bigquery.googleapis.com/projects/my-audit-logs/'
                             'datasets/billing_logs'),
                sink_filter='',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.billing_acct_abcd,
                raw_json='__SINK_1__'
            ),
        ]

        actual_violations = rules_engine.find_violations(
            self.billing_acct_abcd, log_sinks)
        self.assertEqual(set(), actual_violations)

    def test_org_with_no_violations(self):
        """Tests that no violations are produced for a correct organization."""
        rules_engine = self.get_engine_with_valid_rules()

        # Org needs an Audit Log sink, but to any destination.
        log_sinks = [
            LogSink(
                sink_id='audit_logs_to_pubsub',
                destination=('pubsub.googleapis.com/projects/proj-3/topics/'
                             'org-audit-logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                include_children=True,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.org_234,
                raw_json='__SINK_1__'
            )
        ]
        actual_violations = rules_engine.find_violations(
            self.org_234, log_sinks)
        self.assertEqual(set(), actual_violations)

    def test_project_missing_required_sinks(self):
        """Tests violations are produced for project missing required sinks."""
        rules_engine = self.get_engine_with_valid_rules()

        # proj-2 needs an Audit Log sink, by org-level rules, and a pubsub
        # sink, by folder-level rules.
        log_sinks = [
            LogSink(
                sink_id='non_audit_logs_to_bq',
                destination=('bigquery.googleapis.com/projects/my-audit-logs/'
                             'datasets/proj_2_logs'),
                sink_filter='logName:"logs/non-cloudaudit.googleapis.com"',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.proj_2,
                raw_json='__SINK_1__'
            ),
            LogSink(
                sink_id='compute_logs_saver',
                destination=('bigquery.googleapis.com/projects/proj_2/'
                             'datasets/compute_logs'),
                sink_filter='resource.type="gce_instance"',
                include_children=False,
                writer_identity=('serviceAccount:p12345-67890@'
                                 'gcp-sa-logging.iam.gserviceaccount.com'),
                parent=self.proj_2,
                raw_json='__SINK_2__'
            )
        ]

        actual_violations = rules_engine.find_violations(
            self.proj_2, log_sinks)
        expected_violations = set([
            lsre.Rule.RuleViolation(
                resource_name='proj-2',
                resource_type='project',
                resource_id='proj-2',
                full_name='organization/234/folder/56/project/proj-2/',
                rule_name='Require Audit Log sinks in all projects.',
                rule_index=0,
                violation_type='LOG_SINK_VIOLATION',
                sink_destination=('^bigquery\\.googleapis\\.com\\/projects\\/'
                                  'my\\-audit\\-logs\\/datasets\\/.+$'),
                sink_filter=('^logName\\:\\"logs\\/'
                             'cloudaudit\\.googleapis\\.com\\"$'),
                sink_include_children='*',
                resource_data=''
            ),
            lsre.Rule.RuleViolation(
                resource_name='proj-2',
                resource_type='project',
                resource_id='proj-2',
                full_name='organization/234/folder/56/project/proj-2/',
                rule_name='Require a PubSub sink in folder-56 projects.',
                rule_index=3,
                violation_type='LOG_SINK_VIOLATION',
                sink_destination='^pubsub\\.googleapis\\.com\\/.+$',
                sink_filter='^$',
                sink_include_children='*',
                resource_data=''
            )
        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_project_whitelist_violation(self):
        """Tests violations are produced for non-whitelisted sinks."""
        rules_engine = self.get_engine_with_valid_rules()

        # proj-3 can only have BigQuery sinks.
        log_sinks = [
            LogSink(
                sink_id='audit_logs_to_bq',
                destination=('bigquery.googleapis.com/projects/my-audit-logs/'
                             'datasets/proj_1_logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.proj_3,
                raw_json='__SINK_1__'
            ),
            LogSink(
                sink_id='audit_logs_to_pubsub',
                destination=('pubsub.googleapis.com/projects/proj-3/topics/'
                             'proj-audit-logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                include_children=True,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.proj_3,
                raw_json='__SINK_2__'
            )
        ]

        actual_violations = rules_engine.find_violations(
            self.proj_3, log_sinks)
        expected_violations = set([
            lsre.Rule.RuleViolation(
                resource_name='projects/proj-3/sinks/audit_logs_to_pubsub',
                resource_type='sink',
                resource_id='audit_logs_to_pubsub',
                full_name='organization/234/project/proj-3/audit_logs_to_pubsub/',
                rule_name='Only allow BigQuery sinks in Proj-1 and Proj-3.',
                rule_index=4,
                violation_type='LOG_SINK_VIOLATION',
                sink_destination=('pubsub.googleapis.com/projects/proj-3/'
                                  'topics/proj-audit-logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                sink_include_children=True,
                resource_data='__SINK_2__'
            )
        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_folder_blacklist_violation(self):
        """Tests violations are produced for blacklisted sinks."""
        rules_engine = self.get_engine_with_valid_rules()

        # Rules disallow any folder-level LogSinks.
        log_sinks = [
            LogSink(
                sink_id='audit_logs_to_bq',
                destination=('bigquery.googleapis.com/projects/my-audit-logs/'
                             'datasets/folder_logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.folder_56,
                raw_json='__SINK_1__'
            )
        ]

        actual_violations = rules_engine.find_violations(
            self.folder_56, log_sinks)
        expected_violations = set([
            lsre.Rule.RuleViolation(
                resource_name='folders/56/sinks/audit_logs_to_bq',
                resource_type='sink',
                resource_id='audit_logs_to_bq',
                full_name='organization/234/folder/56/audit_logs_to_bq/',
                rule_name='Disallow folder sinks.',
                rule_index=2,
                violation_type='LOG_SINK_VIOLATION',
                sink_destination=('bigquery.googleapis.com/projects/'
                                  'my-audit-logs/datasets/folder_logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                sink_include_children=False,
                resource_data='__SINK_1__')

        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_billing_account_with_whitelist_violations(self):
        """Tests violations are produced for billing account sinks."""
        rules_engine = self.get_engine_with_valid_rules()

        log_sinks = [
            LogSink(
                sink_id='billing_logs',
                destination=('bigquery.googleapis.com/projects/my-audit-logs/'
                             'datasets/wrong_dataset'),
                sink_filter='',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.billing_acct_abcd,
                raw_json='__SINK_1__'
            ),
        ]

        actual_violations = rules_engine.find_violations(
            self.billing_acct_abcd, log_sinks)
        expected_violations = set([
            lsre.Rule.RuleViolation(
                resource_type='sink',
                resource_id='billing_logs',
                resource_name='billingAccounts/ABCD-1234/sinks/billing_logs',
                full_name='organization/234/billingAccount/ABCD-1234/billing_logs/',
                rule_name=('Only allow Billing Account sinks to audit logs '
                           'project.'),
                rule_index=6,
                violation_type='LOG_SINK_VIOLATION',
                sink_destination=('bigquery.googleapis.com/projects/'
                                  'my-audit-logs/datasets/wrong_dataset'),
                sink_filter='',
                sink_include_children=False,
                resource_data='__SINK_1__')

        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_org_missing_required_sinks(self):
        """Tests violations are produced for an org missing required sinks."""
        rules_engine = self.get_engine_with_valid_rules()

        # Org needs an Audit Log sink, including children.
        log_sinks = [
            LogSink(
                sink_id='sink_not_including_children',
                destination=('pubsub.googleapis.com/projects/proj-3/topics/'
                             'org-audit-logs'),
                sink_filter='logName:"logs/cloudaudit.googleapis.com"',
                include_children=False,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.org_234,
                raw_json='__SINK_1__'
            ),
            LogSink(
                sink_id='sink_with_wrong_filter',
                destination=('pubsub.googleapis.com/projects/proj-3/topics/'
                             'org-more-logs'),
                sink_filter='logName:"logs/otherapi.googleapis.com"',
                include_children=True,
                writer_identity='serviceAccount:logs@test.gserviceaccount.com',
                parent=self.org_234,
                raw_json='__SINK_2__'
            )
        ]
        actual_violations = rules_engine.find_violations(
            self.org_234, log_sinks)
        expected_violations = set([
            lsre.Rule.RuleViolation(
                resource_name='234',
                resource_type='organization',
                resource_id='234',
                full_name='organization/234/',
                rule_name='Require an Org Level audit log sink.',
                rule_index=1,
                violation_type='LOG_SINK_VIOLATION',
                sink_destination='^.*$',
                sink_filter=('^logName\\:\\"logs\\/'
                             'cloudaudit\\.googleapis\\.com\\"$'),
                sink_include_children=True,
                resource_data=''
            )
        ])
        self.assertEqual(expected_violations, actual_violations)

    def test_add_invalid_rules(self):
      """Tests that adding invalid rules raises exceptions."""
      rule_book = self.lsre.LogSinkRuleBook(global_configs=None)
      valid_resource = {
          'type': 'organization',
          'applies_to': 'children',
          'resource_ids': ['1234']
      }
      valid_sink_spec = {
          'destination': 'bigquery.*',
          'filter': '',
          'include_children': '*'
      }
      rule_book.add_rule(
          {
              'name': 'Valid rule',
              'resource': [valid_resource],
              'sink': valid_sink_spec,
              'mode': 'whitelist'
          }, 0)
      bad_rules = [
          {},
          {
              'name': 'Mising Resource',
              'mode': 'whitelist',
              'sink': valid_sink_spec,
          }, {
              'name': 'Mising sink',
              'resource': [valid_resource],
              'mode': 'whitelist',
          }, {
              'name': 'Bad mode',
              'resource': [valid_resource],
              'sink': valid_sink_spec,
              'mode': 'other',
          }, {
              'name': 'Bad resource type',
              'resource': [{
                  'type': 'bucket',
                  'applies_to': 'self',
                  'resource_ids': ['bucket-1']
              }],
              'sink': valid_sink_spec,
              'mode': 'whitelist'
          }, {
              'name': 'Bad applies to type',
              'resource': [{
                  'type': 'folder',
                  'applies_to': 'self_and_children',
                  'resource_ids': ['56']
              }],
              'sink': valid_sink_spec,
              'mode': 'whitelist'
          }, {
              'name': 'Bad applies to type',
              'resource': [{
                  'type': 'billing_account',
                  'applies_to': 'children',
                  'resource_ids': ['ABCD-1234']
              }],
              'sink': valid_sink_spec,
              'mode': 'whitelist'
          }, {
              'name': 'Empty resource_ids',
              'resource': [{
                  'type': 'project',
                  'applies_to': 'self',
                  'resource_ids': []
              }],
              'sink': valid_sink_spec,
              'mode': 'whitelist'
          }, {
              'name': 'Missing filter',
              'resource': [valid_resource],
              'sink': {
                  'destination': 'bigquery.*',
                  'include_children': '*'
              },
              'mode': 'whitelist'
          }, {
              'name': 'Bad include_children',
              'resource': [valid_resource],
              'sink': {
                  'destination': 'bigquery.*',
                  'filter': '*',
                  'include_children': 'Yes'
              },
              'mode': 'whitelist'
          }
      ]
      for rule in bad_rules:
          with self.assertRaises(InvalidRulesSchemaError):
              rule_book.add_rule(rule, 1)


if __name__ == '__main__':
    unittest.main()
