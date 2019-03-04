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

"""Tests the Folder resource"""

import mock
import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_api import cloud_resource_manager as crm
from google.cloud.forseti.common.gcp_type import folder
from google.cloud.forseti.common.gcp_type import organization
from google.cloud.forseti.common.gcp_type import resource


_FOLDER_JSON = """
{
 "name": "folders/987",
 "parent": "organizations/234",
 "displayName": "My folder",
 "lifecycleState": "ACTIVE",
 "createTime": "2017-02-09T22:02:07.769Z"
}"""


class FolderTest(ForsetiTestCase):
    """Test Folder resource."""

    def setUp(self):
        self.folder1 = folder.Folder(
            '12345',
            display_name='My folder',
            lifecycle_state=folder.FolderLifecycleState.ACTIVE)
        self.org_234 = organization.Organization(
            '234',
            display_name='Organization 234',
            full_name='organization/234/',
            data='fake_org_data_234')

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

    def test_create_folder_from_json(self):
        """Tests creation of a folder from a JSON string."""
        my_folder = folder.Folder.from_json(self.org_234, _FOLDER_JSON)
        self.assertEqual('987', my_folder.id)
        self.assertEqual('folder', my_folder.type)
        self.assertEqual('folders/987', my_folder.name)
        self.assertEqual('My folder', my_folder.display_name)
        self.assertEqual('organization/234/folder/987/', my_folder.full_name)
        self.assertEqual(folder.FolderLifecycleState.ACTIVE,
                         my_folder.lifecycle_state)

    def test_create_parentless_folder_from_json(self):
        """Tests creation of a folder without a parent from a JSON string."""
        my_folder = folder.Folder.from_json(None, _FOLDER_JSON)
        self.assertEqual('987', my_folder.id)
        self.assertEqual('folder', my_folder.type)
        self.assertEqual('folders/987', my_folder.name)
        self.assertEqual('My folder', my_folder.display_name)
        self.assertEqual('folder/987/', my_folder.full_name)
        self.assertEqual(folder.FolderLifecycleState.ACTIVE,
                         my_folder.lifecycle_state)



if __name__ == '__main__':
    unittest.main()
