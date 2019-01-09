# Copyright 2019 The Forseti Security Authors. All rights reserved.
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
"""A Role Resource.
See: https://cloud.google.com/iam/reference/rest/
"""

import json

from google.cloud.forseti.common.gcp_type import resource


class Role(resource.Resource):
    """Role resource."""

    RESOURCE_NAME_FMT = 'roles/%s'

    def __init__(
            self,
            role_id,
            data=None,
            display_name=None,
            parent=None):
        """Initialize.
        Args:
            role_id (str): The role's unique GCP ID, with the format
                "organizations/{ORGANIZATION_ID}/roles/{ROLE_NAME}" or
                "projects/{PROJECT_ID}/roles/{ROLE_NAME}".
            full_name (str): The full resource name and ancestry.
            data (str): Resource representation of the dataset.
            name (str): Name of the role should be the same as its ID.
            display_name (str): The dataset's display name.
            parent (Resource): The parent Resource.
        """
        super(Role, self).__init__(
            resource_id=role_id,
            resource_type=resource.ResourceType.ROLE,
            name=role_id,
            display_name=display_name,
            parent=parent)
        self.data = data
        print role_id, self.name

    def get_permissions(self):
        """Get permissions of the role.
        Returns:
            list: Permissions list of the role.
        """
        return json.loads(self.data).get('includedPermissions', [])

    @classmethod
    def from_json(cls, parent, json_string):
        """Create a role from a JSON string.

        Args:
            parent (Resource): resource this role belongs to.
            json_string(str): JSON string of a IAM API response.

        Returns:
            Role: role resource.
        """
        role_dict = json.loads(json_string)
        role_id = role_dict['name']
        return cls(
            parent=parent,
            role_id=role_id,
            display_name=role_id,
            data=json_string,
        )
