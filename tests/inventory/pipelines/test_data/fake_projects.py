#!/usr/bin/env python
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

"""Test project data."""

FAKE_PROJECTS = [
  {
    'projects': [
      {
        'name': 'project1',
        'parent': {
          'type': 'organization',
          'id': '888888888888'
        },
        'projectId': 'project1',
        'projectNumber': '25621943694',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-10-22T16:57:36.096Z'
      },
      {
        'name': 'project2',
        'parent': {
          'type': 'organization',
          'id': '888888888888'
        },
        'projectId': 'project2',
        'projectNumber': '94226340476',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-11-13T05:32:10.930Z'
      },
      {
        'name': 'project3',
        'parent': {
          'type': 'organization',
          'id': '888888888888'
        },
        'projectId': 'project3',
        'projectNumber': '133851422272',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-11-13T05:32:49.377Z'
      },
      {
        'name': 'project4',
        'projectId': 'project4',
        'projectNumber': '133851422244',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-11-13T05:32:49.377Z'
      },
      {
        'name': 'project5',
        'parent': {
          'type': 'organization',
          'id': '888888888888'
        },
        'projectId': 'project5',
        'projectNumber': '133851422255',
        'lifecycleState': 'ACTIVE'
      }
    ]
  },
  {
    'projects': [
      {
        'name': 'project6',
        'parent': {
          'type': 'organization',
          'id': '888888888888'
        },
        'projectId': 'project6',
        'projectNumber': '25621943666',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-10-22T16:57:36.066Z'
      },
      {
        'name': 'project7',
        'parent': {
          'type': 'organization',
          'id': '888888888888'
        },
        'projectId': 'project7',
        'projectNumber': '94226340477',
        'lifecycleState': 'ACTIVE',
        'createTime': '2016-11-13T05:32:10.977Z'
      }
    ]
  }
]


EXPECTED_LOADABLE_PROJECTS = [
    {
        'project_name': 'project1',
        'create_time': '2016-10-22 16:57:36',
        'parent_id': '888888888888',
        'project_number': '25621943694',
        'parent_type': 'organization',
        'project_id': 'project1',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"name": "project1", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project1", "projectNumber": "25621943694", "lifecycleState": "ACTIVE", "createTime": "2016-10-22T16:57:36.096Z"}',
    },
    {
        'project_name': 'project2',
        'create_time': '2016-11-13 05:32:10',
        'parent_id': '888888888888',
        'project_number': '94226340476',
        'parent_type': 'organization',
        'project_id': 'project2',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"name": "project2", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project2", "projectNumber": "94226340476", "lifecycleState": "ACTIVE", "createTime": "2016-11-13T05:32:10.930Z"}',
    },
    {
        'project_name': 'project3',
        'create_time': '2016-11-13 05:32:49',
        'parent_id': '888888888888',
        'project_number': '133851422272',
        'parent_type': 'organization',
        'project_id': 'project3',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"name": "project3", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project3", "projectNumber": "133851422272", "lifecycleState": "ACTIVE", "createTime": "2016-11-13T05:32:49.377Z"}',
    },
    {
        'project_name': 'project4',
        'create_time': '2016-11-13 05:32:49',
        'parent_id':None,
        'project_number': '133851422244',
        'parent_type':None,
        'project_id': 'project4',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"projectId": "project4", "lifecycleState": "ACTIVE", "name": "project4", "createTime": "2016-11-13T05:32:49.377Z", "projectNumber": "133851422244"}',
    },
    {
        'project_name': 'project5',
        'create_time': None,
        'parent_id': '888888888888',
        'project_number': '133851422255',
        'parent_type': 'organization',
        'project_id': 'project5',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"projectId": "project5", "lifecycleState": "ACTIVE", "name": "project5", "parent": {"type": "organization", "id": "888888888888"}, "projectNumber": "133851422255"}',
    },
    {
        'project_name': 'project6',
        'create_time': '2016-10-22 16:57:36',
        'parent_id': '888888888888',
        'project_number': '25621943666',
        'parent_type': 'organization',
        'project_id': 'project6',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"name": "project6", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project6", "projectNumber": "25621943666", "lifecycleState": "ACTIVE", "createTime": "2016-10-22T16:57:36.066Z"}',
    },
    {
        'project_name': 'project7',
        'create_time': '2016-11-13 05:32:10',
        'parent_id': '888888888888',
        'project_number': '94226340477',
        'parent_type': 'organization',
        'project_id': 'project7',
        'lifecycle_state': 'ACTIVE',
        'raw_project': '{"name": "project7", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project7", "projectNumber": "94226340477", "lifecycleState": "ACTIVE", "createTime": "2016-11-13T05:32:10.977Z"}',
    }
]
