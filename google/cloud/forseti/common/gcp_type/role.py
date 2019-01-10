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

ROLE_ID_PARENT_TYPE_INDEX = 0
ROLE_ID_PARENT_ID_INDEX = 1
ROLE_ID_TYPE_INDEX = 2
ROLE_ID_NAME_INDEX = 3


def _get_res_id_from_role_id(role_id):
    """Get role's ID from its given GCP ID.

    Args:
        role_id (str): resource ID (in inventory) of role.

    Returns:
        str: role ID; None if the given resource ID is incorrect.
    """
    split_id = role_id.split('/')
    if len(split_id) == 4:
        return split_id[3]
    return None


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
            data (str): Resource representation of the role.
            display_name (str): Title of the role.
            parent (Resource): The parent Resource.
        """
        super(Role, self).__init__(
            resource_id=_get_res_id_from_role_id(role_id),
            resource_type=resource.ResourceType.ROLE,
            name=role_id,
            display_name=display_name,
            parent=parent)
        self.data = data
        if parent and parent.full_name:
            self.full_name = '%srole/%s/' % (parent.full_name, self.id)
        else:
            self.full_name = 'role/%s/' % self.id

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
        return cls(
            parent=parent,
            role_id=role_dict['name'],
            display_name=role_dict.get('title'),
            data=json_string,
        )
