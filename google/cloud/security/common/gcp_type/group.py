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
"""Representation of a Google Group.

See: https://developers.google.com/admin-sdk/directory/v1/reference/groups
"""

from google.cloud.security.common.gcp_type import resource


class Group(resource.Resource):
    """Google Group."""

    def __init__(self, group_id, parent=None):
        """Initialize.

        Args:
            group_id: String of the group id.
        """
        super(Group, self).__init__(
            resource_id=group_id,
            resource_type=resource.ResourceType.GROUP,
            parent=parent)        

    def exists(self):
        """Verify that the resource exists in GCP."""
        pass
