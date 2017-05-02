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

"""Test group members data."""

FAKE_GROUP_MEMBERS = [
    {
       'kind': 'admin#directory#member',
       'etag': '\"abcd1234ABCD1234\"',
       'id': '11111',
       'email': 'writer@my-gcp-project.iam.gserviceaccount.com',
       'role': 'MEMBER',
       'type': 'USER',
       'status': 'ACTIVE'
    },
    {
       'kind': 'admin#directory#member',
       'etag': '\"efgh1234EFGH1234\"',
       'id': '22222',
       'email': 'myuser@mydomain.com',
       'role': 'MEMBER',
       'type': 'USER',
       'status': 'ACTIVE'
    },
    {
       'kind': 'admin#directory#member',
       'etag': '\"hijk1234HIJK1234\"',
       'id': '33333',
       'role': 'MEMBER',
       'type': 'USER',
       'status': 'ACTIVE'
    },
]

FAKE_GROUP_MEMBERS_2 = [
    {
       'kind': 'admin#directory#member',
       'etag': '\"abcd1234ABCD1234\"',
       'id': '44444',
       'email': 'reader@my-gcp-project.iam.gserviceaccount.com',
       'role': 'MEMBER',
       'type': 'USER',
       'status': 'ACTIVE'
    },
    {
       'kind': 'admin#directory#member',
       'etag': '\"efgh1234EFGH1234\"',
       'id': '55555',
       'email': 'myuser2@mydomain.com',
       'role': 'OWNER',
       'type': 'USER',
       'status': 'ACTIVE'
    }
]

EXPECTED_LOADABLE_GROUP_MEMBERS = [
    {
        'group_id': 'mygroup',
        'member_kind': 'admin#directory#member',
        'member_role': 'MEMBER',
        'member_type': 'USER',
        'member_status': 'ACTIVE',
        'member_id': '11111',
        'member_email': 'writer@my-gcp-project.iam.gserviceaccount.com',
        'raw_member': '{"status": "ACTIVE", "kind": "admin#directory#member", "email": "writer@my-gcp-project.iam.gserviceaccount.com", "etag": "\\"abcd1234ABCD1234\\"", "role": "MEMBER", "type": "USER", "id": "11111"}'
    },
    {
        'group_id': 'mygroup',
        'member_kind': 'admin#directory#member',
        'member_role': 'MEMBER',
        'member_type': 'USER',
        'member_status': 'ACTIVE',
        'member_id': '22222',
        'member_email': 'myuser@mydomain.com',
        'raw_member': '{"status": "ACTIVE", "kind": "admin#directory#member", "email": "myuser@mydomain.com", "etag": "\\"efgh1234EFGH1234\\"", "role": "MEMBER", "type": "USER", "id": "22222"}'
    },
    {
        'group_id': 'mygroup',
        'member_kind': 'admin#directory#member',
        'member_role': 'MEMBER',
        'member_type': 'USER',
        'member_status': 'ACTIVE',
        'member_id': '33333',
        'member_email': None,
        'raw_member': '{"status": "ACTIVE", "kind": "admin#directory#member", "etag": "\\"hijk1234HIJK1234\\"", "role": "MEMBER", "type": "USER", "id": "33333"}'
    },
    {
        'group_id': 'mygroup2',
        'member_kind': 'admin#directory#member',
        'member_role': 'MEMBER',
        'member_type': 'USER',
        'member_status': 'ACTIVE',
        'member_id': '44444',
        'member_email': 'reader@my-gcp-project.iam.gserviceaccount.com',
        'raw_member': '{"status": "ACTIVE", "kind": "admin#directory#member", "email": "reader@my-gcp-project.iam.gserviceaccount.com", "etag": "\\"abcd1234ABCD1234\\"", "role": "MEMBER", "type": "USER", "id": "44444"}'
    },
    {
        'group_id': 'mygroup2',
        'member_kind': 'admin#directory#member',
        'member_role': 'OWNER',
        'member_type': 'USER',
        'member_status': 'ACTIVE',
        'member_id': '55555',
        'member_email': 'myuser2@mydomain.com',
        'raw_member': '{"status": "ACTIVE", "kind": "admin#directory#member", "email": "myuser2@mydomain.com", "etag": "\\"efgh1234EFGH1234\\"", "role": "OWNER", "type": "USER", "id": "55555"}'
    }
]

FAKE_GROUPS_MEMBERS_MAP = [
    ('mygroup',  FAKE_GROUP_MEMBERS),
    ('mygroup2', FAKE_GROUP_MEMBERS_2)
]

FAKE_GROUP_IDS = [
    'a111', 'a222', 'a333', 'a444', 'a555',
    'a666', 'a777', 'a888', 'a999', 'a000',
]

EXPECTED_CALL_LIST = [
    ['a111', 'a222', 'a333'],
    ['a444', 'a555', 'a666'],
    ['a777', 'a888', 'a999'],
    ['a000'],
]
