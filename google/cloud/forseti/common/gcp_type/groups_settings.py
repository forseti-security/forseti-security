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

"""A GroupsSettings object.

See:
https://developers.google.com/admin-sdk/groups-settings/v1/reference/groups
"""

import json

from google.cloud.forseti.common.gcp_type import resource
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


class GroupsSettings(resource.Resource):
    """Represents the GroupsSettings resource."""

    # pylint: disable=invalid-name
    def __init__(
            self, email, whoCanAdd=None, whoCanJoin=None,
            whoCanViewMembership=None, whoCanViewGroup=None, whoCanInvite=None,
            allowExternalMembers=None, whoCanLeaveGroup=None):
        """Initialize.

        Args:
            email (str): The unique group email.
            whoCanAdd (str): Setting for who can add.
            whoCanJoin (str): Setting for who can join.
            whoCanViewMembership (str): Setting for who can view membership.
            whoCanViewGroup (str): Setting for who can view group.
            whoCanInvite (str): Setting for who can invite to group.
            allowExternalMembers (str): Setting for are external members
            allowed.
            whoCanLeaveGroup (str): Setting for who can leave group.
        """
        super(GroupsSettings, self).__init__(
            resource_id=email,
            name=email,
            resource_type=resource.ResourceType.GROUPS_SETTINGS)
        self.whoCanAdd = whoCanAdd
        self.whoCanJoin = whoCanJoin
        self.whoCanViewMembership = whoCanViewMembership
        self.whoCanViewGroup = whoCanViewGroup
        self.whoCanInvite = whoCanInvite
        self.allowExternalMembers = bool(allowExternalMembers)
        self.whoCanLeaveGroup = whoCanLeaveGroup

    @classmethod
    def from_json(cls, email, settings):
        """Returns a new GroupsSettingws object from a JSON object.

        Args:
            email (str): The unique Gsuite Group email.
            settings(str): JSON string of a GroupsSettings Gsuites API response.

        Returns:
           GroupsSettings: A new GroupsSettings object.
        """
        settings = json.loads(settings)
        return cls(
            email=email,
            whoCanAdd=settings.get('whoCanAdd'),
            whoCanJoin=settings.get('whoCanJoin'),
            whoCanViewMembership=settings.get('whoCanViewMembership'),
            whoCanViewGroup=settings.get('whoCanViewGroup'),
            whoCanInvite=settings.get('whoCanInvite'),
            allowExternalMembers=settings.get('allowExternalMembers'),
            whoCanLeaveGroup=settings.get('whoCanLeaveGroup'))
