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


class GroupMember(object):
    """Group Member."""

    def __init__(self, rule_def_member):
        """Initialize.

        Args:
            rule_def_member: Dictionary of the Google Group Member from the
                rule definition.
        """
        self.role = rule_def_member.get('role')
        self.type = rule_def_member.get('type')
        self.email = rule_def_member.get('email')

        if (not self.get('role') or
                not self.get('type') or
                not self.get('email')):
            raise errors.InvalidGroupMemberError(
                ('Invalid group member: role={}, type={}, email={}'
                 .format(self.get('role'),
                         self.get('type'),
                         self.get('email'))))
