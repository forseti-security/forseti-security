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

"""Fake folders data."""

FAKE_FOLDERS_DB_ROWS = [
    {'folder_id': '111111111111',
     'name': 'folders/111111111111',
     'display_name': 'Folder1',
     'lifecycle_state': 'ACTIVE',
     'create_time': '2015-09-09 00:01:01',
     'parent_id': '9999',
     'parent_type': 'organization'},
    {'folder_id': '222222222222',
     'name': 'folders/222222222222',
     'display_name': 'Folder2',
     'lifecycle_state': 'ACTIVE',
     'create_time': '2015-10-10 00:02:02',
     'parent_id': None,
     'parent_type': None},
]

FAKE_FOLDERS_RESPONSE = {
    'folders': [
        {
          'name': 'folders/1111111111',
          'display_name': 'Folder1',
          'lifecycleState': 'ACTIVE',
          'parent': 'organizations/9999',
        },
        {
            'name': 'folders/2222222222',
            'display_name': 'Folder2',
            'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'folders/3333333333',
            'display_name': 'Folder3',
            'lifecycleState': 'ACTIVE',
        }
    ]
}

EXPECTED_FAKE_FOLDERS_FROM_API = FAKE_FOLDERS_RESPONSE['folders']

FAKE_FOLDERS_OK_IAM_DB_ROWS = [
    {'folder_id': '1111111111',
     'display_name': 'Folder1',
     'lifecycle_state': 'ACTIVE',
     'parent_id': '9999',
     'parent_type': 'organizations',
     'iam_policy': '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'},
    {'folder_id': '2222222222',
     'display_name': 'Folder2',
     'lifecycle_state': 'ACTIVE',
     'parent_id': None,
     'parent_type': None,
     'iam_policy': '{"bindings": [{"role": "roles/viewer", "members": ["user:d@e.f"]}]}'},
]

FAKE_FOLDERS_BAD_IAM_DB_ROWS = [
    {'folder_id': '1111111111',
     'display_name': 'Folder1',
     'lifecycle_state': 'ACTIVE',
     'parent_id': '9999',
     'parent_type': 'organizations',
     'iam_policy': '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'},
    {'folder_id': '2222222222',
     'display_name': 'Folder2',
     'lifecycle_state': 'ACTIVE',
     'parent_id': None,
     'parent_type': None,
     'iam_policy': ''},
]

FAKE_FOLDERS_API_RESPONSE1 = {
    'folders': [
        {
            'displayName': 'folder-1',
            'name': 'folders/111',
            'parent': 'folders/1111111',
            'lifecycleState': 'ACTIVE',
            'parent': 'organizations/9999'
        },
        {
            'displayName': 'folder-2',
            'name': 'folders/222',
            'parent': 'folders/2222222',
            'lifecycleState': 'DELETE_REQUESTED'
        },
        {
            'displayName': 'folder-3',
            'name': 'folders/333',
            'parent': 'folders/3333333',
            'lifecycleState': 'ACTIVE'
        },
    ]
}

EXPECTED_FAKE_FOLDERS1 = FAKE_FOLDERS_API_RESPONSE1['folders']

FAKE_FOLDERS_LIST_API_RESPONSE1 = {
    'folders': [
        f for f in FAKE_FOLDERS_API_RESPONSE1['folders']
            if f['parent'] == 'organizations/9999'
    ]
}

EXPECTED_FAKE_FOLDERS_LIST1 = FAKE_FOLDERS_LIST_API_RESPONSE1['folders']

FAKE_ACTIVE_FOLDERS_API_RESPONSE1 = {
    'folders': [
        f for f in FAKE_FOLDERS_API_RESPONSE1['folders']
            if f['lifecycleState'] == 'ACTIVE'
    ]
}

EXPECTED_FAKE_ACTIVE_FOLDERS1 = FAKE_ACTIVE_FOLDERS_API_RESPONSE1['folders']
