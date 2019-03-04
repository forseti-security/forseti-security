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

"""A Folder Resource."""

import json

from google.cloud.forseti.common.gcp_type import resource


class FolderLifecycleState(resource.LifecycleState):
    """Represents the Folder's LifecycleState."""
    pass


class Folder(resource.Resource):
    """Folder Resource."""

    RESOURCE_NAME_FMT = 'folders/%s'

    def __init__(
            self,
            folder_id,
            full_name=None,
            data=None,
            name=None,
            display_name=None,
            parent=None,
            lifecycle_state=FolderLifecycleState.UNSPECIFIED):
        """Initialize.

        Args:
            folder_id (str): The folder id number.
            full_name (str): The full resource name and ancestory.
            data (str): Resource representation of the folder.
            name (str): The folder unique GCP name, i.e. "folders/{id}".
            display_name (str): The folder display name.
            parent (Resource): The parent Resource.
            lifecycle_state (LifecycleState): The folder's lifecycle state.
        """
        super(Folder, self).__init__(
            resource_id=folder_id,
            resource_type=resource.ResourceType.FOLDER,
            name=name,
            display_name=display_name,
            parent=parent,
            lifecycle_state=lifecycle_state)
        self.full_name = full_name
        self.data = data

    @classmethod
    def from_json(cls, parent, json_string):
        """Creates a Folder from a JSON string.

        Args:
            parent (Resource): resource this folder belongs to.
            json_string (str): JSON string of a folder GCP resource.

        Returns:
            Folder: folder resource.
        """
        folder_dict = json.loads(json_string)
        name = folder_dict['name']
        folder_id = name.split('/')[-1]
        full_name = 'folder/{}/'.format(folder_id)
        if parent:
            full_name = '{}{}'.format(parent.full_name, full_name)
        lifecycle = folder_dict.get('lifecycleState',
                                    FolderLifecycleState.UNSPECIFIED)
        return cls(
            folder_id=folder_id,
            full_name=full_name,
            data=json_string,
            name=name,
            display_name=folder_dict.get('displayName'),
            parent=parent,
            lifecycle_state=lifecycle)
