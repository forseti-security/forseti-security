# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Test group data."""

FAKE_GROUPS = [
    {
        'nonEditableAliases': ['aaaaa@foo.com'],
        'kind': 'admin#directory#group',
        'name': 'aaaaa',
        'adminCreated': True,
        'directMembersCount': '1',
        'email': 'aaaaa@foo.com',
        'etag': '"pCd5iosDe_tWdPv4ke8sAYzlGK8/oWZC62Ysx9kAKLlW23uoKQlYu3k"',
        'id': '11111',
        'description': ''
    },
    {
        'nonEditableAliases': ['bbbbb@foo.com'],
        'kind': 'admin#directory#group',
        'name': 'bbbbb',
        'adminCreated': False,
        'directMembersCount': '1',
        'email': 'bbbbb@foo.com',
        'etag': '"pCd5iosDe_tWdPv4ke8sAYzlGK8/cglP2U9YgiKA9zjJ-DvxjotnaLU"',
        'id': '22222',
        'description': ''
    },
    {
        'nonEditableAliases': ['ccccc@foo.com'],
        'kind': 'admin#directory#group',
        'name': 'CCCCC Users',
        'adminCreated': True,
        'directMembersCount': '4',
        'email': 'ccccc@foo.com',
        'etag': '"pCd5iosDe_tWdPv4ke8sAYzlGK8/kQ2NdfLnWQTiAs-FCSEKJRaipxw"',
        'id': '33333',
        'description': 'Members of this group will be allowed to perform bar.'
    }
]


EXPECTED_LOADABLE_GROUPS = [
    {
        'group_id': '11111',
        'group_email': 'aaaaa@foo.com',
        'group_kind': 'admin#directory#group',
        'direct_member_count': '1',
        'raw_group': '{"nonEditableAliases": ["aaaaa@foo.com"], "kind": "admin#directory#group", "etag": "\\"pCd5iosDe_tWdPv4ke8sAYzlGK8/oWZC62Ysx9kAKLlW23uoKQlYu3k\\"", "name": "aaaaa", "adminCreated": true, "description": "", "directMembersCount": "1", "email": "aaaaa@foo.com", "id": "11111"}',
    },
    {
        'group_id': '22222',
        'group_email': 'bbbbb@foo.com',
        'group_kind': 'admin#directory#group',
        'direct_member_count': '1',
        'raw_group': '{"nonEditableAliases": ["bbbbb@foo.com"], "kind": "admin#directory#group", "etag": "\\"pCd5iosDe_tWdPv4ke8sAYzlGK8/cglP2U9YgiKA9zjJ-DvxjotnaLU\\"", "name": "bbbbb", "adminCreated": false, "description": "", "directMembersCount": "1", "email": "bbbbb@foo.com", "id": "22222"}',
    },
    {
        'group_id': '33333',
        'group_email': 'ccccc@foo.com',
        'group_kind': 'admin#directory#group',
        'direct_member_count': '4',
        'raw_group': '{"nonEditableAliases": ["ccccc@foo.com"], "kind": "admin#directory#group", "etag": "\\"pCd5iosDe_tWdPv4ke8sAYzlGK8/kQ2NdfLnWQTiAs-FCSEKJRaipxw\\"", "name": "CCCCC Users", "adminCreated": true, "description": "Members of this group will be allowed to perform bar.", "directMembersCount": "4", "email": "ccccc@foo.com", "id": "33333"}',
    }
]
