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

"""Tests the OrgResourceRelDao."""

from tests.unittest_utils import ForsetiTestCase
import mock
import unittest

from google.cloud.forseti.common.data_access import _db_connector
from google.cloud.forseti.common.data_access import folder_dao
from google.cloud.forseti.common.data_access import org_resource_rel_dao
from google.cloud.forseti.common.data_access import organization_dao
from google.cloud.forseti.common.data_access import project_dao
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import project


class OrgResourceRelDaoTest(ForsetiTestCase):
    """Test OrgResourceRelDaoTest."""

    @mock.patch.object(project_dao.ProjectDao, '__init__', autospec=True)
    @mock.patch.object(folder_dao.FolderDao, '__init__', autospec=True)
    @mock.patch.object(organization_dao.OrganizationDao, '__init__', autospec=True)
    def setUp(self, mock_org_dao, mock_folder_dao, mock_project_dao):
        mock_org_dao.return_value = None
        mock_folder_dao.return_value = None
        mock_project_dao.return_value = None
        self.org_res_rel_dao = org_resource_rel_dao.OrgResourceRelDao({})

        # TODO: move this to separate module
        self.fake_org = organization.Organization(
            organization_id=1,
            display_name='Org 1')
        self.fake_folder1 = folder.Folder(
            folder_id=11,
            display_name='Folder 1',
            parent=self.fake_org)
        self.fake_folder2 = folder.Folder(
            folder_id=22,
            display_name='Folder 2',
            parent=self.fake_folder1)
        self.fake_project1 = project.Project(
            project_number=111,
            project_id='project-1',
            display_name='Project 1',
            parent=self.fake_folder2)

        self.fake_timestamp = '1234567890'

    @mock.patch.object(project_dao.ProjectDao, 'get_project')
    @mock.patch.object(folder_dao.FolderDao, 'get_folder')
    @mock.patch.object(organization_dao.OrganizationDao, 'get_organization')
    def test_find_ancestors_from_project(
            self,
            mock_get_org,
            mock_get_folder,
            mock_get_project):
        """Find ancestors."""
        mock_get_org.return_value = self.fake_org
        mock_get_folder.side_effect = [self.fake_folder2, self.fake_folder1]
        mock_get_project.return_value = self.fake_project1

        actual1 = self.org_res_rel_dao.find_ancestors(
            self.fake_project1, self.fake_timestamp)

        self.assertEqual(
            [self.fake_folder2, self.fake_folder1, self.fake_org],
            actual1)

    @mock.patch.object(project_dao.ProjectDao, 'get_project')
    @mock.patch.object(folder_dao.FolderDao, 'get_folder')
    @mock.patch.object(organization_dao.OrganizationDao, 'get_organization')
    def test_find_ancestors_from_folder(
            self,
            mock_get_org,
            mock_get_folder,
            mock_get_project):
        """Find ancestors."""
        mock_get_org.return_value = self.fake_org
        mock_get_folder.side_effect = [self.fake_folder1]

        actual2 = self.org_res_rel_dao.find_ancestors(
            self.fake_folder2, self.fake_timestamp)

        self.assertEqual(
            [self.fake_folder1, self.fake_org],
            actual2)

    @mock.patch.object(project_dao.ProjectDao, 'get_project')
    @mock.patch.object(folder_dao.FolderDao, 'get_folder')
    @mock.patch.object(organization_dao.OrganizationDao, 'get_organization')
    def test_find_ancestors_from_org(
            self,
            mock_get_org,
            mock_get_folder,
            mock_get_project):
        """Find ancestors."""
        mock_get_org.return_value = self.fake_org

        actual3 = self.org_res_rel_dao.find_ancestors(
            self.fake_org, self.fake_timestamp)

        self.assertEqual(
            [],
            actual3)

    def test_get_resource_ancestors_from_full_name(self):

        # resource is organization
        mock_starting_resource = mock.MagicMock()
        mock_starting_resource.type = 'organization'
        mock_starting_resource.id = 'org1'
        resource_ancestors = (
            org_resource_rel_dao.find_ancestors_by_hierarchial_name(
                mock_starting_resource,
                'organization/org1/'))

        self.assertEquals(1, len(resource_ancestors))

        # resource is project
        mock_starting_resource.type = 'project'
        mock_starting_resource.id = 'project3'
        resource_ancestors = (
            org_resource_rel_dao.find_ancestors_by_hierarchial_name(
                mock_starting_resource,
                'organization/org1/folder/folder2/project/project3/'))

        self.assertEquals(3, len(resource_ancestors))
        self.assertEquals(mock_starting_resource, resource_ancestors[0])
        self.assertEquals('folder2', resource_ancestors[1].id)
        self.assertEquals('org1', resource_ancestors[2].id)        

        # resource has multiple folders, and subproject resources
        mock_starting_resource.type = 'firewall'        
        mock_starting_resource.id = 'firewall5'
        resource_ancestors = (
            org_resource_rel_dao.find_ancestors_by_hierarchial_name(
                mock_starting_resource,
                ('organization/org1/folder/folder2/folder/folder3/'
                 'project/project4/firewall/firewall5/')))
        
        self.assertEquals(5, len(resource_ancestors))
        self.assertEquals(mock_starting_resource, resource_ancestors[0])
        self.assertEquals('project4', resource_ancestors[1].id)
        self.assertEquals('folder3', resource_ancestors[2].id)
        self.assertEquals('folder2', resource_ancestors[3].id)        
        self.assertEquals('org1', resource_ancestors[4].id)


if __name__ == '__main__':
    unittest.main()
