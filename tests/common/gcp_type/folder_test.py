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

"""Tests the Folder resource"""

from google.apputils import basetest
from google.cloud.security.common.gcp_type.folder import Folder
from google.cloud.security.common.gcp_type.folder import FolderLifecycleState
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil


class FolderTest(basetest.TestCase):
    """Test Folder resource."""

    def test_create_folder_getters_are_correct(self):
        """Test whether the Folder getter methods return expected data."""
        my_folder_id = 'my-folderid-1'
        my_folder_name = 'My folder name'
        folder = Folder(my_folder_id, folder_name=my_folder_name,
                          lifecycle_state=FolderLifecycleState.ACTIVE)
        self.assertEqual(my_folder_id, folder.get_id())
        self.assertEqual(my_folder_name, folder.get_name())
        self.assertEqual(ResourceType.FOLDER, folder.get_type())
        self.assertEqual(None, folder.get_parent())
        self.assertEqual(FolderLifecycleState.ACTIVE,
                         folder.get_lifecycle_state())

    def test_folder_type_is_folder(self):
        """Test whether the created Folder's type is ResourceType.FOLDER."""
        folder = Folder('folder-id', 12345)
        self.assertEqual(ResourceType.FOLDER, folder.get_type())

    def test_project_in_folder_returns_folder_ancestor(self):
        """Test whether the ancestry includes the folder, for a project."""
        folder = Folder('folder-1', folder_name='My folder name')
        project = Project('my-project-id', 333,
                          project_name='My project',
                          parent=folder)
        expected = [folder]
        actual = [a for a in project.get_ancestors(include_self=False)]
        self.assertEqual(expected, actual)

    def test_folder_no_parent_returns_empty_ancestors(self):
        """Test that a folder with no parents has no ancestors."""
        folder = Folder('my-folder-id', folder_name='My folder')
        expected = []
        actual = [a for a in folder.get_ancestors(include_self=False)]
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    basetest.main()
