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
"""A Folder Resource."""

from google.cloud.security.common.gcp_type.resource import LifecycleState
from google.cloud.security.common.gcp_type.resource import Resource
from google.cloud.security.common.gcp_type.resource import ResourceType

# pylint: disable=too-few-public-methods
# TODO: Investigate improving so as to not use the disable.
class FolderLifecycleState(LifecycleState):
    """Represents the Folder's LifecycleState."""
    pass


class Folder(Resource):
    """Folder Resource."""

    def __init__(self, folder_id, folder_name=None,
                 lifecycle_state=FolderLifecycleState.UNSPECIFIED):
        """Initalize.

        Args:
            folder_id: The string folder id.
            folder_name: The string folder name.
            lifecycle_state: The folder's lifecycle state.
        """
        super(Folder, self).__init__(
            resource_id=folder_id,
            resource_type=ResourceType.FOLDER,
            resource_name=folder_name,
            parent=None,
            lifecycle_state=lifecycle_state)

    def exists(self):
        """Verify that the folder exists.

        Returns:
            True if we can get the folder from GCP, otherwise False.
        """
        # TODO: enable for folders
        return False
