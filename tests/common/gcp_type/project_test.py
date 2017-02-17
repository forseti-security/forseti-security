# Copyright 2017 Google Inc.
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

"""Tests the Project resource."""

import mock

from google.apputils import basetest
from google.cloud.security.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.security.common.gcp_type.folder import Folder
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import ProjectLifecycleState
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil

class ProjectTest(basetest.TestCase):

    def setUp(self):
        self.project1 = Project('project-id-1', 123451, 'Project 1')

    def test_create_project_getters_are_correct(self):
        """Test Project getters returns correct values."""
        my_project_id = 'my-projectid-1'
        my_project_number = 1234567890
        my_project_name = 'My project name'
        project = Project(my_project_id, my_project_number,
                          project_name=my_project_name,
                          lifecycle_state=ProjectLifecycleState.ACTIVE)
        self.assertEqual(my_project_id, project.get_id())
        self.assertEqual(my_project_number, project.get_project_number())
        self.assertEqual(my_project_name, project.get_name())
        self.assertEqual(ResourceType.PROJECT, project.get_type())
        self.assertEqual(None, project.get_parent())
        self.assertEqual(ProjectLifecycleState.ACTIVE,
                         project.get_lifecycle_state())

    def test_project_type_is_project(self):
        """Test Project created is a ResourceType.PROJECT type."""
        self.assertEqual(ResourceType.PROJECT, self.project1.get_type())

    def test_project_equals_other_project_is_true(self):
        """Test that Project == another Project."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project1 = Project(id_1, number_1, project_name=name_1)

        id_2 = 'my-project-1'
        number_2 = 1234567890
        name_2 = 'My project 1'
        project2 = Project(id_2, number_2, project_name=name_2)

        self.assertTrue(project1 == project2)

    def test_project_notequals_other_project_is_true(self):
        """Test that a Project does not equal a Project of different id."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project1 = Project(id_1, number_1, project_name=name_1)

        id_2 = 'my-project-2'
        number_2 = 1234567891
        name_2 = 'My project 2'
        project2 = Project(id_2, number_2, project_name=name_2)

        self.assertTrue(project1 != project2)

    def test_project_notequals_org_is_true(self):
        """Test that a Project != Organization."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project = Project(id_1, number_1, project_name=name_1)

        id_2 = '1234567890'
        name_2 = 'My org 1'
        org = Organization(id_2, org_name=name_2)

        self.assertTrue(project != org)

    def test_project_in_org_returns_org_ancestor(self):
        """Test that a Project with Org ancestor returns Org ancestor."""
        org = Organization('1234567890', org_name='My org name')
        project = Project('my-project-id', 333,
                          project_name='My project',
                          parent=org)
        expected = [org]
        actual = [a for a in project.get_ancestors(include_self=False)]
        self.assertEqual(expected, actual)

    def test_project_no_org_returns_empty_ancestors(self):
        """Test that a Project with no parent has no ancestors."""
        project = Project('my-project-id', 333,
                          project_name='My project')
        expected = []
        actual = [a for a in project.get_ancestors(include_self=False)]
        self.assertEqual(expected, actual)

    def test_project_ancestors_include_self(self):
        """Test Project ancestors when including self."""
        org = Organization('1234567890', org_name='My org name')
        project = Project('my-project-id', 333,
                          project_name='My project',
                          parent=org)
        expected = [project, org]
        actual = [a for a in project.get_ancestors()]
        self.assertEqual(expected, actual)

    @mock.patch.object(CloudResourceManagerClient, 'get_project',
                       autospec=True)
    def test_org_exists(self, mock_crm):
        """Tests that the organization exists."""
        mock_crm.return_value = True
        self.assertTrue(self.project1.exists())


if __name__ == '__main__':
    basetest.main()
