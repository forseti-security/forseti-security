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

"""Utility functions for parsing various data."""


def parse_member_info(member):
    """Parse out the component info in the member string.

    Args:
        member: String of a member.  Example: user:foo@bar.com

    Returns:
        member_type: String of the member type.
        member_name: String of the name portion of the member.
        member_domain: String of the domain of the member.
    """
    member_type, email = member.split(":", 1)

    if '@' in email:
        member_name, member_domain = email.split('@', 1)
    else:
        # Member then is really something like domain:google.com
        member_name = ''
        member_domain = email

    return member_type, member_name, member_domain
