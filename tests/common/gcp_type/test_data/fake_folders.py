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

"""Fake folders data."""

# TODO
FAKE_FOLDERS_OK_IAM_DB_ROWS = [
    [1111111111, 'project-1', 'Project 1', 'ACTIVE', None, None, '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'],
    [2222222222, 'project-2', 'Project 2', 'ACTIVE', None, None, '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'],
]

# TODO
FAKE_FOLDERS_BAD_IAM_DB_ROWS = [
    [1111111111, 'project-1', 'Project 1', 'ACTIVE', None, None, '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'],
    [2222222222, 'project-2', 'Project 2', 'ACTIVE', None, None, ''],
]

FAKE_FOLDERS_API_RESPONSE1 = {
    'folders': [
        {
            'displayName': 'folder-1',
            'name': 'folders/111',
            'parent': 'organizations/1111111',
            'lifecycleState': 'ACTIVE'
        },
        {
            'displayName': 'folder-2',
            'name': 'folders/222',
            'parent': 'organizations/2222222',
            'lifecycleState': 'DELETE_REQUESTED'
        },
        {
            'displayName': 'folder-3',
            'name': 'folders/333',
            'parent': 'folders/111',
            'lifecycleState': 'ACTIVE'
        },
    ]
}

EXPECTED_FAKE_FOLDERS1 =  [FAKE_FOLDERS_API_RESPONSE1]

EXPECTED_FAKE_ACTIVE_FOLDERS1 = [{
    'folders': [
        f for f in FAKE_FOLDERS_API_RESPONSE1['folders']
            if f['lifecycleState'] == 'ACTIVE'
    ]
}]
