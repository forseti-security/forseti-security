# Copyright 2017 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test data for group dao tests."""

GET_GROUP_MEMBERS_SIDE_EFFECT = [
    (
        {'group_id': '11111',
         'member_email': 'foo-group@mycompany.com',
         'member_id': '22222',
         'member_role': 'MEMBER',
         'member_type': 'GROUP'},
        {'group_id': '11111',
         'member_email': 'aaaaa@mycompany.com',
         'member_id': '115155963703470907150',
         'member_role': 'MEMBER',
         'member_type': 'USER'},
        {'group_id': '11111',
         'member_email': 'bbbbb@mycompany.com',
         'member_id': '104880549572841397018',
         'member_role': 'MEMBER',
         'member_type': 'USER'}
    ),
    (
        {'group_id': '22222',
         'member_email': 'ccccc@mycompany.com',
         'member_id': '103758279426504283647',
         'member_role': 'OWNER',
         'member_type': 'USER'},
    )
]

EXPECTED_ALL_MEMBERS = [
    {'member_role': 'MEMBER',
     'group_id': '11111',
     'member_email': 'foo-group@mycompany.com',
     'member_type': 'GROUP',
     'member_id': '22222'},
    {'member_role': 'MEMBER',
     'group_id': '11111',
     'member_email': 'aaaaa@mycompany.com',
     'member_type': 'USER',
     'member_id': '115155963703470907150'},
    {'member_role': 'MEMBER',
     'group_id': '11111',
     'member_email': 'bbbbb@mycompany.com',
     'member_type': 'USER',
     'member_id': '104880549572841397018'},
    {'member_role': 'OWNER',
     'group_id': '22222',
     'member_email': 'ccccc@mycompany.com',
     'member_type': 'USER',
     'member_id': '103758279426504283647'}
]
