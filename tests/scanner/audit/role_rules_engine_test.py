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

"""Tests the RoleRulesEngine."""

import copy
import itertools
import json
import mock
import tempfile
import unittest
import yaml

from datetime import datetime, timedelta
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.forseti.scanner.audit import base_rules_engine as bre
from google.cloud.forseti.scanner.audit import errors as audit_errors
from google.cloud.forseti.scanner.audit import role_rules_engine as rre
from google.cloud.forseti.scanner.scanners import role_scanner as rrs
from tests.scanner.test_data import fake_role_scanner_data as frsd
from tests.unittest_utils import get_datafile_path
from tests.unittest_utils import ForsetiTestCase


import collections
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners import retention_scanner

def get_rules_engine_with_rule(rule):
    """Create a rule engine based on a yaml file string"""
    with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
        f.write(rule)
        f.flush()
        rules_engine = rre.RoleRulesEngine(
            rules_file_path=f.name)
        rules_engine.build_rule_book()
    return rules_engine


class RoleRulesEngineTest(ForsetiTestCase):
    """Tests for the BigqueryRulesEngine."""

    def setUp(self):
        """Set up."""

    def test_invalid_rule_with_no_role_name(self):
        """Test that a rule without role_name cannot be created"""
        yaml_str_invalid_rule="""
rules:
  - name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - type: project
      resource_ids: ['*']

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_invalid_rule)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_permissions(self):
        """Test that a rule without permissions cannot be created"""
        yaml_str_invalid_rule="""
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    resource:
    - type: project
      resource_ids: ['*']

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_invalid_rule)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_resource(self):
        """Test that a rule without resource cannot be created"""
        yaml_str_invalid_rule="""
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_invalid_rule)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_resource_type(self):
        """Test that a rule without resource:type cannot be created"""
        yaml_str_invalid_rule="""
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - resource_ids: ['*']

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_invalid_rule)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_resource_id(self):
        """Test that a rule without resource:resource_ids cannot be created"""
        yaml_str_invalid_rule="""
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - type: project

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_invalid_rule)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    yaml_str_multiple_rules_on_projects = """
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - type: project
      resource_ids: ['*']
  - role_name: "forsetiCloudsqlViewer"
    name: "forsetiCloudsqlViewer rule backupRuns"
    permissions:
    - "cloudsql.backupRuns.get"
    - "cloudsql.backupRuns.list"
    resource:
    - type: project
      resource_ids: ['def-project-1']
  - role_name: "forsetiCloudsqlViewer"
    name: "forsetiCloudsqlViewer rule databases"
    permissions:
    - "cloudsql.databases.get"
    - "cloudsql.databases.list"
    resource:
    - type: project
      resource_ids: ['def-project-2']

"""

    def test_no_violation_for_rules_on_wildcard(self):
        """Role is a correct forsetiBigqueryViewer that should have no violation."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_rules_on_projects)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.get",
                                                 "bigquery.tables.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [])

    def test_violations_for_rules_on_wildcard(self):
        """Role is a incorrect forsetiBigqueryViewer that should have violations."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_rules_on_projects)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [frsd.generate_violation(fake_role, 0, 'forsetiBigqueryViewer rule')])

    def test_no_violation_for_rules(self):
        """Role is a correct forsetiCloudsqlViewer(project 1) that should have no violation."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_rules_on_projects)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiCloudsqlViewer',
                                                ["cloudsql.backupRuns.get",
                                                 "cloudsql.backupRuns.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [])

    def test_violations_for_rules(self):
        """Role is a incorrect forsetiCloudsqlViewer(project 1) that should have violations."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_rules_on_projects)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiCloudsqlViewer',
                                                ["cloudsql.databases.get",
                                                 "cloudsql.databases.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [frsd.generate_violation(fake_role, 1, 'forsetiCloudsqlViewer rule backupRuns')])

    yaml_str_multiple_rules_on_organizations = """
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - type: organization
      resource_ids: ['123456']

"""

    def test_no_violation_for_rules_on_org(self):
        """Role is a correct forsetiBigqueryViewer that should have no violation."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_rules_on_organizations)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.get",
                                                 "bigquery.tables.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))

        self.assertEqual(got_violations, [])

    def test_violations_for_rules_on_org(self):
        """Role is a incorrect forsetiBigqueryViewer that should have violations."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_rules_on_organizations)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))

        self.assertEqual(got_violations, [frsd.generate_violation(fake_role, 0, 'forsetiBigqueryViewer rule')])

    yaml_str_multiple_resource_ids_rules = """
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - type: project
      resource_ids: ['def-project-1', 'def-project-2']

"""

    def test_no_violation_for_rules_with_multi_resource_ids(self):
        """Role is a correct forsetiBigqueryViewer that should have no violation."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_resource_ids_rules)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.get",
                                                 "bigquery.tables.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [])

    def test_role_full_name(self):
        """Test the role has a correct full name"""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_multiple_resource_ids_rules)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))

        data_creater = frsd.FakeRoleDataCreater('forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.get",
                                                 "bigquery.tables.list"], frsd.PROJECT1)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [])


if __name__ == '__main__':
    unittest.main()
