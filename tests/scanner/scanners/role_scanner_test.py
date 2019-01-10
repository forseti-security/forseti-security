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

"""Tests for RoleScanner."""

import collections
import json
import unittest
import mock
import tempfile

from tests.scanner.test_data import fake_role_scanner_data as frsd
from tests.unittest_utils import ForsetiTestCase
from tests.unittest_utils import get_datafile_path
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.scanner.audit import role_rules_engine as rre
from google.cloud.forseti.scanner.scanners import role_scanner


def get_mock_role(role_data):
    """Get the mock function for testcases"""

    def _mock_role(_=None, resource_type='role'):
        """Creates a list of GCP resource mocks retrieved by the scanner"""
        if resource_type != 'role':
            raise ValueError(
                'unexpected resource type: got %s, bucket',
                resource_type,
            )

        ret = []
        for data in role_data:
            ret.append(frsd.get_fake_role_resource(data))

        return ret
    return _mock_role


class RoleScannerTest(ForsetiTestCase):

    def setUp(self):
        """Set up."""

    def test_retrieve_and_find_violation(self):
        """Test a rule that includes more than one bucket IDs"""

        rule_yaml = """
rules:
  - role_name: "forsetiBigqueryViewer"
    name: "forsetiBigqueryViewer rule"
    permissions:
    - "bigquery.datasets.get"
    - "bigquery.tables.get"
    - "bigquery.tables.list"
    resource:
    - type: project
      resource_ids: ['def-project-1']
  - role_name: "forsetiCloudsqlViewer"
    name: "forsetiCloudsqlViewer rule"
    permissions:
    - "cloudsql.backupRuns.get"
    - "cloudsql.backupRuns.list"
    resource:
    - type: organization
      resource_ids: ['*']
  - role_name: "anotherForsetiRole"
    name: "All anotherForsetiRole from everywhere must obey this rule"
    permissions:
    - "cloudsql.instances.get"
    - "cloudsql.instances.list"
    resource:
    - type: role
      resource_ids: ['anotherForsetiRole']

"""

        role_test_data=[
            frsd.FakeRoleDataInput(
                name='forsetiBigqueryViewer',
                permission=['bigquery.datasets.get', 'bigquery.tables.get', 'bigquery.tables.list'],
                parent=frsd.PROJECT1
            ),
            frsd.FakeRoleDataInput(
                name='forsetiBigqueryViewer',
                permission=['bigquery.datasets.get', 'bigquery.tables.list'],
                parent=frsd.PROJECT2
            ),
            frsd.FakeRoleDataInput(
                name='forsetiCloudsqlViewer',
                permission=['cloudsql.backupRuns.get', 'cloudsql.backupRuns.list','cloudsql.instances.get'],
                parent=frsd.PROJECT1
            ),
            frsd.FakeRoleDataInput(
                name='anotherForsetiRole',
                permission=['cloudsql.instances.get', 'cloudsql.instances.list', 'bigquery.tables.list'],
                parent=frsd.PROJECT2
            ),
        ]

        _mock_bucket = get_mock_role(role_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(None, 'role')

            self.scanner = role_scanner.RoleScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            role_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(role_info)

            res_map = {}
            for i in _fake_bucket_list:
                res_map[i.id] = i

            expected_violations = set([
                frsd.generate_violation(res_map['forsetiCloudsqlViewer'], 1, 'forsetiCloudsqlViewer rule'),
                frsd.generate_violation(res_map['anotherForsetiRole'], 2, 'All anotherForsetiRole from everywhere must obey this rule'),
            ])

            self.assertEqual(expected_violations, set(all_violations))

    def test_violations_on_rules_with_multiple_resource_ids(self):
        """Test a rule that includes more than one bucket IDs"""

        rule_yaml = """
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

        role_test_data=[
            frsd.FakeRoleDataInput(
                name='forsetiBigqueryViewer',
                permission=['bigquery.datasets.get', 'bigquery.tables.get', 'bigquery.tables.list'],
                parent=frsd.PROJECT1
            ),
            frsd.FakeRoleDataInput(
                name='forsetiBigqueryViewer',
                permission=['bigquery.datasets.get', 'bigquery.tables.list'],
                parent=frsd.PROJECT2
            ),
        ]

        _mock_bucket = get_mock_role(role_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(None, 'role')

            self.scanner = role_scanner.RoleScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            role_info = self.scanner._retrieve()
            all_violations = self.scanner._find_violations(role_info)

            res_map = {}
            for i in _fake_bucket_list:
                res_map[i.id] = i

            expected_violations = set([
                frsd.generate_violation(res_map['forsetiBigqueryViewer'], 0, 'forsetiBigqueryViewer rule'),
            ])

            self.assertEqual(expected_violations, set(all_violations))


    def test_scanner_run(self):
        """Test a rule that includes more than one bucket IDs"""

        rule_yaml = """
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

        role_test_data=[
            frsd.FakeRoleDataInput(
                name='forsetiBigqueryViewer',
                permission=['bigquery.datasets.get', 'bigquery.tables.get', 'bigquery.tables.list'],
                parent=frsd.PROJECT1
            ),
            frsd.FakeRoleDataInput(
                name='forsetiBigqueryViewer',
                permission=['bigquery.datasets.get', 'bigquery.tables.list'],
                parent=frsd.PROJECT2
            ),
        ]

        _mock_bucket = get_mock_role(role_test_data)

        with tempfile.NamedTemporaryFile(suffix='.yaml') as f:
            f.write(rule_yaml)
            f.flush()
            _fake_bucket_list = _mock_bucket(None, 'role')

            self.scanner = role_scanner.RoleScanner(
                {}, {}, mock.MagicMock(), '', '', f.name)

            mock_data_access = mock.MagicMock()
            mock_data_access.scanner_iter.side_effect = _mock_bucket

            mock_service_config = mock.MagicMock()
            mock_service_config.model_manager = mock.MagicMock()
            mock_service_config.model_manager.get.return_value = (
                mock.MagicMock(), mock_data_access)
            self.scanner.service_config = mock_service_config

            self.scanner.run()
