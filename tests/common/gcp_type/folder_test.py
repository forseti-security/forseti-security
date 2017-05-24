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

import mock

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_type import folder
from google.cloud.security.common.gcp_type import project
from google.cloud.security.common.gcp_type import resource


class FolderTest(ForsetiTestCase):
    """Test Folder resource."""

    def setUp(self):
        self.folder1 = folder.Folder(
            '12345',
            display_name='My folder',
            lifecycle_state=folder.FolderLifecycleState.ACTIVE)

    def test_create_folder_getters_are_correct(self):
        """Test whether the Folder getter methods return expected data."""
        my_folder_id = '123456'
        my_folder_name = 'My folder name'
        f1 = folder.Folder(my_folder_id, display_name=my_folder_name,
                           lifecycle_state=folder.FolderLifecycleState.ACTIVE)
        self.assertEqual(my_folder_id, f1.id)
        self.assertEqual(
            folder.Folder.RESOURCE_NAME_FMT % my_folder_id, f1.name)
        self.assertEqual(my_folder_name, f1.display_name)
        self.assertEqual(resource.ResourceType.FOLDER, f1.type)
        self.assertEqual(None, f1.parent)
        self.assertEqual(folder.FolderLifecycleState.ACTIVE,
                         f1.lifecycle_state)

    @mock.patch.object(
        crm.CloudResourceManagerClient, 'get_folder', autospec=True)
    def test_folder_exists(self, mock_crm):
        """Tests that the folder exists."""
        mock_crm.return_value = True
        self.assertTrue(self.folder1.exists())


if __name__ == '__main__':
    unittest.main()
