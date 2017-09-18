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

"""Fake groups data.

TODO: consolidate with other fake group test data.
"""

FAKE_GROUPS_DB_ROWS = [
    {
        'group_id': '1111aaaa1',
        'member_role': 'OWNER',
        'member_type': 'USER',
        'member_email': 'owneruser@foo.xyz'
    },
    {
        'group_id': '2222bbbb2',
        'member_role': 'MEMBER',
        'member_type': 'GROUP',
        'member_email': 'group2@foo.xyz'
    },
    {
        'group_id': '2222bbbb2',
        'member_role': 'OWNER',
        'member_type': 'GROUP',
        'member_email': 'ownergroup@foo.xyz'
    },
    {
        'group_id': '1111aaaa1',
        'member_role': 'MEMBER',
        'member_type': 'USER',
        'member_email': 'user4@foo.xyz'
    },
    {
        'group_id': '1111aaaa1',
        'member_role': 'MEMBER',
        'member_type': 'USER',
        'member_email': 'user5@foo.xyz'
    },
]
