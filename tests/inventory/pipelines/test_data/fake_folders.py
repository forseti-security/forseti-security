#!/usr/bin/env python
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

"""Test folder data."""

FAKE_FOLDERS = [
    {
        'name': 'folders/111111111111',
        'displayName': 'Folder1',
        'lifecycleState': 'ACTIVE',
        'parent': 'organizations/7777',
        'createTime': '2016-10-22T16:57:36.096Z'
    },
    {
        'name': 'folders/222222222222',
        'displayName': 'Folder2',
        'lifecycleState': 'ACTIVE',
        'parent': 'folders/111111111111',
        'createTime': '2016-11-13T05:32:10.930Z'
    },
    {
        'name': 'folders/333333333333',
        'displayName': 'Folder3',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-11-13T05:32:49.377Z'
    },
    {
        'name': 'folders/444444444444',
        'displayName': 'Folder4',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-10-22T16:57:36.066Z'
    },
    {
        'name': 'folders/555555555555',
        'displayName': 'Folder5',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-11-13T05:32:10.977Z'
    }
]


EXPECTED_LOADABLE_FOLDERS = [
    {
        'folder_id': '111111111111',
        'name': 'folders/111111111111',
        'display_name': 'Folder1',
        'lifecycle_state': 'ACTIVE',
        'create_time': '2016-10-22 16:57:36',
        'parent_id': '7777',
        'parent_type': 'organization',
        'raw_folder': ''
    },
    {
        'folder_id': '222222222222',
        'name': 'folders/222222222222',
        'display_name': 'Folder2',
        'lifecycle_state': 'ACTIVE',
        'create_time': '2016-11-13 05:32:10',
        'parent_id': '111111111111',
        'parent_type': 'folder',
        'raw_folder': ''
    },
    {
        'folder_id': '333333333333',
        'name': 'folders/333333333333',
        'display_name': 'Folder3',
        'lifecycle_state': 'ACTIVE',
        'create_time': '2016-11-13 05:32:49',
        'parent_id': None,
        'parent_type': None,
        'raw_folder': ''
    },
    {
        'folder_id': '444444444444',
        'name': 'folders/444444444444',
        'display_name': 'Folder4',
        'lifecycle_state': 'ACTIVE',
        'create_time': '2016-10-22 16:57:36',
        'parent_id': None,
        'parent_type': None,
        'raw_folder': ''
    },
    {
        'folder_id': '555555555555',
        'name': 'folders/555555555555',
        'display_name': 'Folder5',
        'lifecycle_state': 'ACTIVE',
        'create_time': '2016-11-13 05:32:10',
        'parent_id': None,
        'parent_type': None,
        'raw_folder': ''
    }
]
