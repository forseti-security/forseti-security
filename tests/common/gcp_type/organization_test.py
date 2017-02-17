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

"""Tests the Organization resource."""

import mock

from google.apputils import basetest
from google.cloud.security.common.gcp_api.cloud_resource_manager import CloudResourceManagerClient
from google.cloud.security.common.gcp_type.folder import Folder
from google.cloud.security.common.gcp_type.organization import OrgLifecycleState
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil


class OrganizationTest(basetest.TestCase):

    def setUp(self):
        self.org1 = Organization('1234567890',
                                 org_name='My org',
                                 lifecycle_state=OrgLifecycleState.ACTIVE)

    def test_create_org_getters_are_correct(self):
        """Test the Organization getters."""
        my_org_id = '1234567890'
        my_org_name = 'My org name'
        org = Organization(my_org_id, org_name=my_org_name,
                           lifecycle_state=OrgLifecycleState.ACTIVE)
        self.assertEqual(my_org_id, org.get_id())
        self.assertEqual(my_org_name, org.get_name())
        self.assertEqual(ResourceType.ORGANIZATION, org.get_type())
        self.assertEqual(None, org.get_parent())
        self.assertEqual(OrgLifecycleState.ACTIVE,
                         org.get_lifecycle_state())

    def test_org_type_is_organization(self):
        """Test that a created Organization is a ResourceType.ORGANIZATION."""
        self.assertEqual(ResourceType.ORGANIZATION, self.org1.get_type())

    def test_org_equals_other_org_is_true(self):
        """Test equality of an Organization to another is true."""
        id_1 = '1234567890'
        name_1 = 'My org 1'
        org1 = Organization(id_1, org_name=name_1)

        id_2 = '1234567890'
        name_2 = 'My org 1'
        org2 = Organization(id_2, org_name=name_2)

        self.assertTrue(org1 == org2)

    def test_org_notequals_other_org_is_true(self):
        """Test inequality of an Organization to another."""
        id_1 = '1234567890'
        name_1 = 'My org 1'
        org1 = Organization(id_1, org_name=name_1)

        id_2 = '1234567891'
        name_2 = 'My org 2'
        org2 = Organization(id_2, org_name=name_2)

        self.assertTrue(org1 != org2)

    def test_org_notequals_project_is_true(self):
        """Test inequality of an Organization to a Project."""
        id_1 = 'my-project-1'
        number_1 = 1234567890
        name_1 = 'My project 1'
        project = Project(id_1, number_1, project_name=name_1)

        id_2 = '1234567890'
        name_2 = 'My org 1'
        org = Organization(id_2, org_name=name_2)

        self.assertTrue(project != org)

    def test_org_empty_ancestors(self):
        """Test that an Organization has no ancestors."""
        expected = []
        actual = [a for a in self.org1.get_ancestors(include_self=False)]
        self.assertEqual(expected, actual)

    def test_org_ancestors_include_self(self):
        """Test getting ancestry when including self."""
        expected = [self.org1]
        actual = [a for a in self.org1.get_ancestors()]
        self.assertEqual(expected, actual)

    @mock.patch.object(CloudResourceManagerClient, 'get_organization',
                       autospec=True)
    def test_org_exists(self, mock_crm):
        """Tests that the organization exists."""
        mock_crm.return_value = True
        self.assertTrue(self.org1.exists())


if __name__ == '__main__':
    basetest.main()
