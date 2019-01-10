# Copyright 2019 The Forseti Security Authors. All rights reserved.
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

"""Tests the Role resource"""

import json
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import role as rl
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project


class RoleTest(ForsetiTestCase):
    """Test Role resource."""

    def setUp(self):
        """Set up parent GCP resources for tests."""
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

    def test_create_from_json(self):
        """Tests creating a Role from a JSON string."""
        json_string = (
            r'{"description": "Access to view BigQuery datasets and tables, but not table contents", '
            r'"etag": "BwV1mM8N7WM=", "includedPermissions": ["bigquery.datasets.get", '
            r'"bigquery.tables.get", "bigquery.tables.list"], "name": '
            r'"projects/proj-1/roles/forsetiBigqueryViewer", '
            r'"title": "Forseti BigQuery Metadata Viewer"}')

        role = rl.Role.from_json(self.proj_1, json_string)

        self.assertEqual('forsetiBigqueryViewer', role.id)
        self.assertEqual('role', role.type)
        self.assertEqual('projects/proj-1/roles/forsetiBigqueryViewer',
                         role.name)
        self.assertEqual(['bigquery.datasets.get',
                          'bigquery.tables.get',
                          'bigquery.tables.list'],
                         role.get_permissions())


if __name__ == '__main__':
    unittest.main()
