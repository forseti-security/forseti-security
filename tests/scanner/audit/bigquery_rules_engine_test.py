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

"""Tests the BigqueryRulesEngine."""

import copy
import itertools
import json
import mock
import unittest
import yaml

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import bigquery_access_controls as bq_acls
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import bigquery_rules_engine as bqe
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path
from tests.scanner.audit.data import bigquery_test_rules
from tests.scanner.test_data import fake_bigquery_scanner_data


def create_list_of_bq_objects_from_data():
    fake_bigquery_scanner_list = []
    for data in fake_bigquery_scanner_data.BIGQUERY_DATA:
        # TODO: use bq_acls.from_json for better integration testing.
        temp_test_bq_acl = bq_acls.BigqueryAccessControls(
            project_id=data['project_id'],
            dataset_id=data['dataset_id'],
            full_name=data['full_name'],
            role=data['role'],
            special_group=data.get('access_special_group'),
            user_email=data.get('access_user_by_email'),
            domain=data.get('access_domain'),
            group_email=data.get('access_group_by_email'),
            view={},
            raw_json=data['resource_data'])
        fake_bigquery_scanner_list.append(temp_test_bq_acl)
    return fake_bigquery_scanner_list

# TODO: More tests need to be added that cover the rule attributes and how they
#    are evaluated
class BigqueryRulesEngineTest(ForsetiTestCase):
    """Tests for the BigqueryRulesEngine."""

    def setUp(self):
        """Set up."""
        self.rule_index = 0
        self.bqe = bqe
        self.bqe.LOGGER = mock.MagicMock()
        self.fake_timestamp = '12345'

        self.org = organization.Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234',
        )

        self.project = project.Project(
            'p1',
            project_number=11223344,
            display_name='My project 1',
            parent=self.org,
            full_name='organization/234/project/p1/',
            data='fake_project_data_2341',
        )

    def test_build_rule_book_from_local_yaml_file_works(self):
        """Test that a RuleBook is built correctly with a yaml file."""
        rules_local_path = get_datafile_path(__file__,
            'bigquery_test_rules_1.yaml')
        rules_engine = bqe.BigqueryRulesEngine(
                           rules_file_path=rules_local_path)
        rules_engine.build_rule_book()
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

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
        rules_path = 'input/bigquery_test_rules_1.yaml'
        full_rules_path = 'gs://{}/{}'.format(bucket_name, rules_path)
        rules_engine = bqe.BigqueryRulesEngine(rules_file_path=full_rules_path)

        # Read in the rules file
        file_content = None
        with open(get_datafile_path(__file__, 'bigquery_test_rules_1.yaml'),
                  'r') as rules_local_file:
            try:
                file_content = yaml.safe_load(rules_local_file)
            except yaml.YAMLError:
                raise

        mock_load_rules_from_gcs.return_value = file_content

        rules_engine.build_rule_book()
        self.assertEqual(1, len(rules_engine.rule_book.resource_rules_map))

    def test_build_rule_book_no_resource_type_fails(self):
        """Test that a rule without a resource cannot be created."""
        rules_local_path = get_datafile_path(__file__,
            'bigquery_test_rules_2.yaml')
        rules_engine = bqe.BigqueryRulesEngine(
                           rules_file_path=rules_local_path)
        with self.assertRaises(InvalidRulesSchemaError):
            rules_engine.build_rule_book()

    def test_find_violations_blacklist_with_no_violations(self):
        """Test that a rule for a given rule there are no violations."""
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_3.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual([], actual_violations_list)

    def test_find_violations_blacklist_with_violations(self):
        """Test that a rule for a given rule there are violations."""
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_4.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual(
            fake_bigquery_scanner_data.BIGQUERY_EXPECTED_VIOLATION_LIST,
            actual_violations_list)

    def test_find_violations_inapplicable_resource(self):
        # rules are set on org 234
        org = organization.Organization(
            '000',
            display_name='Organization 000',
            full_name='organization/000/',
            data='fake_org_data_000',
        )

        proj = project.Project(
            '111',
            project_number=111,
            display_name='My project 111',
            parent=org,
            full_name='organization/000/project/111/',
            data='fake_project_data_111',
        )

        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_4.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls:
            violation = rules_engine.find_violations(proj, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual([], actual_violations_list)

    def test_find_violations_whitelist_no_violations(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_5.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual([], actual_violations_list)

    def test_find_violations_whitelist_inapplicable_dataset(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_6.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual(
            [],
            actual_violations_list)

    def test_find_violations_whitelist_inapplicable_resource(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_7.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual(
            [],
            actual_violations_list)

    def test_find_violations_whitelist_with_violations(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_8.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual(
            fake_bigquery_scanner_data.BIGQUERY_EXPECTED_VIOLATION_LIST,
            actual_violations_list)

    def test_find_violations_old_style_rules(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_9.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual(
            fake_bigquery_scanner_data.BIGQUERY_EXPECTED_VIOLATION_LIST,
            actual_violations_list)

    def test_find_violations_multiple_dataset_ids(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_10.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual(
            [fake_bigquery_scanner_data.BIGQUERY_EXPECTED_VIOLATION_LIST[0]],
            actual_violations_list)

    def test_find_violations_unset_acl_field(self):
        rules_local_path = get_datafile_path(
            __file__,
            'bigquery_test_rules_11.yaml')
        rules_engine = bqe.BigqueryRulesEngine(rules_local_path)
        rules_engine.build_rule_book()
        fake_bq_acls_data = create_list_of_bq_objects_from_data()
        actual_violations_list = []
        for bqt in fake_bq_acls_data:
            violation = rules_engine.find_violations(self.project, bqt)
            actual_violations_list.extend(violation)
        self.assertEqual([], actual_violations_list)

if __name__ == '__main__':
    unittest.main()
