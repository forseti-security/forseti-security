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

"""Tests the BigqueryRulesEngine."""

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
        rules_engine = rre.RolePermissionRulesEngine(
            rules_file_path=f.name)
        rules_engine.build_rule_book()
    return rules_engine


class RoleRulesEngineTest(ForsetiTestCase):
    """Tests for the BigqueryRulesEngine."""

    def setUp(self):
        """Set up."""

    def test_invalid_rule_with_no_role_id(self):
        """Test that a rule without role_id cannot be created"""
        yaml_str_no_role_id="""
rules:
  - permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_no_role_id)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rule_with_no_permissions(self):
        """Test that a rule without permissions cannot be created"""
        yaml_str_no_permissions="""
rules:
  - role_id: "roles/forsetiBigqueryViewer"

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_no_permissions)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_invalid_rules_with_the_same_name(self):
        """Test that rules with the same role name cannot be created"""
        yaml_str_with_the_same_name="""
rules:
  - role_id: "roles/forsetiBigqueryViewer"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
  - role_id: "roles/forsetiBigqueryViewer"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_with_the_same_name)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            with self.assertRaises(InvalidRulesSchemaError):
                self.scanner = rrs.RoleScanner(
                    {}, {}, mock.MagicMock(), '', '', rules_local_path)

    def test_valid_rules(self):
        """Test that rules with the same role name cannot be created"""
        yaml_str_valid_rules="""
rules:
  - role_id: "roles/forsetiBigqueryViewer"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
  - role_id: "roles/forsetiCloudsqlViewer"
    permissions:
    - "cloudsql.backupRuns.get"
    - "cloudsql.backupRuns.list"
    - "cloudsql.databases.get"
    - "cloudsql.databases.list"
    - "cloudsql.instances.get"
    - "cloudsql.instances.list"
    - "cloudsql.sslCerts.get"
    - "cloudsql.sslCerts.list"
    - "cloudsql.users.list"

"""
        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(yaml_str_valid_rules)
            f.flush()
            rules_local_path = get_datafile_path(__file__, f.name)
            self.scanner = rrs.RoleScanner(
                {}, {}, mock.MagicMock(), '', '', rules_local_path)

    yaml_str_two_role_rule = """
rules:
  - role_id: "roles/forsetiBigqueryViewer"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
  - role_id: "roles/forsetiCloudsqlViewer"
    permissions:
    - "cloudsql.backupRuns.get"
    - "cloudsql.backupRuns.list"
    - "cloudsql.databases.get"
    - "cloudsql.databases.list"
    - "cloudsql.instances.get"
    - "cloudsql.instances.list"
    - "cloudsql.sslCerts.get"
    - "cloudsql.sslCerts.list"
    - "cloudsql.users.list"

"""

    def test_no_violation_in_two_rules(self):
        """Test that a role is correct."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_two_role_rule)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))


        data_creater = frsd.FakeRoleDataCreater('roles/forsetiBigqueryViewer',
                                                ["bigquery.datasets.get",
                                                 "bigquery.tables.get",
                                                 "bigquery.tables.list"], None)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [])

    def test_one_violation_in_two_rules(self):
        """Test that a role is incorrect."""
        rules_engine = get_rules_engine_with_rule(RoleRulesEngineTest.yaml_str_two_role_rule)
        self.assertTrue(1 <= len(rules_engine.rule_book.rules_map))


        data_creater = frsd.FakeRoleDataCreater('roles/forsetiBigqueryViewer',
                                                ["bigquery.tables.get",
                                                 "bigquery.tables.list"], None)

        fake_role = data_creater.get_resource()
        got_violations = list(rules_engine.find_violations(fake_role))
        self.assertEqual(got_violations, [frsd.generate_violation(fake_role, 0)])


if __name__ == '__main__':
    unittest.main()
