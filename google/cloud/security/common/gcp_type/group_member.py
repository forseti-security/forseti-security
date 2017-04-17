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
"""Representation of a Google Group Member.

https://developers.google.com/admin-sdk/directory/v1/reference/members
"""
# pylint: disable=no-member

from google.cloud.security.common.gcp_type import errors


# pylint: disable=too-few-public-methods
class GroupMember(object):
    """Group Member."""

    def __init__(self, member_role, member_type, member_email):
        """Initialize.

        Args:
            member_role: String of the member role, e.g. owner, member, etc.
            member_type: String of the member type, e.g. group, user, etc.
            member_email: String of the member email
        """
        self.member_role = member_role
        self.member_type = member_type
        self.member_email = member_email

        if (not self.member_role or 
            not self.member_type or
            not self.member_email):
            raise errors.InvalidGroupMemberError(
                ('Invalid group member: role={}, type={}, email={}'
                 .format(self.member_role,
                         self.member_type,
                         self.member_email)))
