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

"""Fake projects data.

TODO: consolidate with other fake project test data.
"""

FAKE_PROJECTS_OK_IAM_DB_ROWS = [
    [1111111111, 'project-1', 'Project 1', 'ACTIVE', None, None, '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'],
    [2222222222, 'project-2', 'Project 2', 'ACTIVE', None, None, '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'],
]

FAKE_PROJECTS_BAD_IAM_DB_ROWS = [
    [1111111111, 'project-1', 'Project 1', 'ACTIVE', None, None, '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'],
    [2222222222, 'project-2', 'Project 2', 'ACTIVE', None, None, ''],
]

FAKE_PROJECTS_API_RESPONSE1 = {
    'projects': [
        {
            'name': 'project1',
            'projectId': 'project1',
            'projectNumber': '25621943694',
            'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'project2',
            'projectId': 'project2',
            'projectNumber': '94226340476',
            'lifecycleState': 'DELETE_REQUESTED',
        },
        {
            'name': 'project3',
            'projectId': 'project3',
            'projectNumber': '133851422272',
            'lifecycleState': 'ACTIVE',
        }]
}

EXPECTED_FAKE_PROJECTS1 = [FAKE_PROJECTS_API_RESPONSE1]

EXPECTED_FAKE_ACTIVE_PROJECTS1 = [{
    'projects': [
        p for p in FAKE_PROJECTS_API_RESPONSE1['projects']
            if p['lifecycleState'] == 'ACTIVE'
    ]
}]
