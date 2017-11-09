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

"""Tests the Organization resource."""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.common.gcp_type.organization import OrgLifecycleState
from google.cloud.forseti.common.gcp_type.organization import Organization
from google.cloud.forseti.common.gcp_type.project import Project
from google.cloud.forseti.common.gcp_type.resource import ResourceType


class OrganizationTest(ForsetiTestCase):

    def setUp(self):
        self.org1 = Organization('1234567890',
                                 display_name='My org',
                                 lifecycle_state=OrgLifecycleState.ACTIVE)

    def test_create_org_getters_are_correct(self):
        """Test the Organization getters."""
        my_org_id = '1234567890'
        my_org_name = 'My org name'
        org = Organization(my_org_id, display_name=my_org_name,
                           lifecycle_state=OrgLifecycleState.ACTIVE)
        self.assertEqual(my_org_id, org.id)
        self.assertEqual(my_org_name, org.display_name)
        self.assertEqual(Organization.RESOURCE_NAME_FMT % my_org_id, org.name)
        self.assertEqual(ResourceType.ORGANIZATION, org.type)
        self.assertEqual(None, org.parent)
        self.assertEqual(OrgLifecycleState.ACTIVE,
                         org.lifecycle_state)

    def test_org_type_is_organization(self):
        """Test that a created Organization is a ResourceType.ORGANIZATION."""
        self.assertEqual(ResourceType.ORGANIZATION, self.org1.type)

    def test_equality(self):
        """Test equality of an Organization to another is true."""
        id_1 = '1234567890'
        name_1 = 'My org 1'
        org1 = Organization(id_1, display_name=name_1)

        id_2 = '1234567890'
        name_2 = 'My org 1'
        org2 = Organization(id_2, display_name=name_2)

        self.assertTrue(org1 == org2)

    def test_not_equals(self):
        """Test inequality of an Organization to another."""
        id_1 = '1234567890'
        name_1 = 'My org 1'
        org1 = Organization(id_1, display_name=name_1)

        id_2 = '1234567891'
        name_2 = 'My org 2'
        org2 = Organization(id_2, display_name=name_2)

        self.assertTrue(org1 != org2)

    def test_org_notequals_project(self):
        """Test that an Organization != Project."""
        proj_id = 'my-project-1'
        proj_num = 1234567890
        proj_name = 'My project 1'
        project1 = Project(proj_id, proj_num, display_name=proj_name)

        folder_id = '88888'
        folder_name = 'My folder'
        folder1 = folder.Folder(folder_id, display_name=folder_name)

        org_id = '1234567890'
        org_name = 'My org 1'
        org1 = Organization(org_id, display_name=org_name)

        self.assertTrue(org1 != project1)
        self.assertTrue(org1 != folder1)


if __name__ == '__main__':
    unittest.main()
