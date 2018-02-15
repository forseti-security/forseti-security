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

"""Tests the Project resource."""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type.folder import Folder
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import ProjectLifecycleState
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.gcp_type.resource import ResourceType


class ProjectTest(ForsetiTestCase):

    def setUp(self):
        self.org = Organization('1234567890', display_name='My org name')
        self.folder = Folder('55555', display_name='My folder', parent=self.org)
        self.project1 = Project('project-1',
                                11111,
                                display_name='Project 1')
        self.project2 = Project('project-2',
                                22222,
                                display_name='Project 2',
                                parent=self.org)
        self.project3 = Project('project-3',
                                33333,
                                display_name='Project 3',
                                parent=self.folder)

    def test_create_project_getters_are_correct(self):
        """Test Project getters returns correct values."""
        my_project_id = 'my-projectid-1'
        my_project_number = 1234567890
        my_project_name = 'My project name'
        project = Project(my_project_id, project_number=my_project_number,
                          display_name=my_project_name,
                          lifecycle_state=ProjectLifecycleState.ACTIVE)
        self.assertEqual(my_project_id, project.id)
        self.assertEqual(my_project_number, project.project_number)
        self.assertEqual(
            Project.RESOURCE_NAME_FMT % my_project_id, project.name)
        self.assertEqual(my_project_name, project.display_name)
        self.assertEqual(ResourceType.PROJECT, project.type)
        self.assertEqual(None, project.parent)
        self.assertEqual(ProjectLifecycleState.ACTIVE,
                         project.lifecycle_state)

    def test_project_equals_other_project_is_true(self):
        """Test that Project == another Project."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project1 = Project(id_1, number_1, display_name=name_1)

        id_2 = 'my-project-1'
        number_2 = 1234567890
        name_2 = 'My project 1'
        project2 = Project(id_2, number_2, display_name=name_2)

        self.assertTrue(project1 == project2)

    def test_project_notequals_other_project_is_true(self):
        """Test that a Project does not equal a Project of different id."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project1 = Project(id_1, number_1, display_name=name_1)

        id_2 = 'my-project-2'
        number_2 = 1234567891
        name_2 = 'My project 2'
        project2 = Project(id_2, number_2, display_name=name_2)

        self.assertTrue(project1 != project2)

    def test_project_notequals_org_is_true(self):
        """Test that a Project != Organization."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project = Project(id_1, number_1, display_name=name_1)

        id_2 = '1234567890'
        name_2 = 'My org 1'
        org = Organization(id_2, display_name=name_2)

        self.assertTrue(project != org)


if __name__ == '__main__':
    unittest.main()
