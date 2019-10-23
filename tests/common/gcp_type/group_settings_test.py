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

import unittest

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import groups_settings

EMAIL = 'testgroup@test.com'

_GROUPS_SETTINGS_JSON = """
{
    "allowExternalMembers": "false",
    "email": "testgroup@test.org",
    "name": "TestGroup",
    "whoCanAdd": "ALL_MANAGERS_CAN_ADD",
    "whoCanInvite": "ALL_MANAGERS_CAN_INVITE",
    "whoCanJoin": "INVITED_CAN_JOIN",
    "whoCanLeaveGroup": "ALL_MEMBERS_CAN_LEAVE",
    "whoCanViewMembership": "ALL_IN_DOMAIN_CAN_VIEW",
    "whoCanViewGroup": "ALL_IN_DOMAIN_CAN_VIEW"
}"""


class GroupSettingsTest(ForsetiTestCase):
    """Test Group Settings resource."""

    def test_create_groups_settings_from_json(self):
        """Tests creation of a group settings resource from a JSON string."""
        my_groups_settings = groups_settings.GroupsSettings.from_json(
            email=EMAIL,
            settings=_GROUPS_SETTINGS_JSON)
        self.assertEqual(EMAIL, my_groups_settings.name)
        self.assertFalse(my_groups_settings.allowExternalMembers)
        self.assertEqual('ALL_MANAGERS_CAN_ADD', my_groups_settings.whoCanAdd)
        self.assertEqual('ALL_MANAGERS_CAN_INVITE', my_groups_settings.whoCanInvite)
        self.assertEqual('INVITED_CAN_JOIN', my_groups_settings.whoCanJoin)
        self.assertEqual('ALL_MEMBERS_CAN_LEAVE', my_groups_settings.whoCanLeaveGroup)
        self.assertEqual('ALL_IN_DOMAIN_CAN_VIEW', my_groups_settings.whoCanViewGroup)
        self.assertEqual('ALL_IN_DOMAIN_CAN_VIEW', my_groups_settings.whoCanViewMembership)


if __name__ == '__main__':
    unittest.main()
