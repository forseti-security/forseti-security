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

"""Tests the Lien resource"""

import json
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import lien
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project


class LienTest(ForsetiTestCase):
    """Test Lien resource."""

    def setUp(self):
        """Set up parent GCP resources for tests."""
        self.org_234 = organization.Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

        self.proj_1 = project.Project(
            'proj-1',
            project_number=11223344,
            display_name='My project 1',
            parent=self.org_234,
            full_name='organization/234/project/proj-1/',
            data='fake_project_data_2341')

    def test_create_from_json(self):
        """Tests creating a Lien from a JSON string."""
        json_string = """
{
    "name": "liens/lien-1",
    "parent": "projects/proj-1",
    "restrictions": ["resourcemanager.projects.delete"]
}
"""
        lien_resource = lien.Lien.from_json(self.proj_1, json_string)
        self.assertEqual('lien-1', lien_resource.id)
        self.assertEqual('lien', lien_resource.type)
        self.assertEqual('projects/proj-1/liens/lien-1', lien_resource.name)
        self.assertEqual(['resourcemanager.projects.delete'],
                        lien_resource.restrictions)
        self.assertEqual(json.loads(json_string),
                         json.loads(lien_resource.raw_json))


if __name__ == '__main__':
    unittest.main()
