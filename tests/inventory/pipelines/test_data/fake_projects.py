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

# pylint: disable=line-too-long
EXPECTED_LOADABLE_PROJECTS = [
    {
        'index': '25621943694',
        'resource_key': 'project1',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"name": "project1", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project1", "projectNumber": "25621943694", "lifecycleState": "ACTIVE", "createTime": "2016-10-22T16:57:36.096Z"},
    },
    {

        'index': '94226340476',
        'resource_key': 'project2',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"name": "project2", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project2", "projectNumber": "94226340476", "lifecycleState": "ACTIVE", "createTime": "2016-11-13T05:32:10.930Z"},
    },
    {
        'index': '133851422272',
        'resource_key': 'project3',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"name": "project3", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project3", "projectNumber": "133851422272", "lifecycleState": "ACTIVE", "createTime": "2016-11-13T05:32:49.377Z"},
    },
    {
        'index': '133851422244',
        'resource_key': 'project4',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"projectId": "project4", "lifecycleState": "ACTIVE", "name": "project4", "createTime": "2016-11-13T05:32:49.377Z", "projectNumber": "133851422244"},
    },
    {
        'index': '133851422255',
        'resource_key': 'project5',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"projectId": "project5", "lifecycleState": "ACTIVE", "name": "project5", "parent": {"type": "organization", "id": "888888888888"}, "projectNumber": "133851422255"},
    },
    {
        'index': '25621943666',
        'resource_key': 'project6',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"name": "project6", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project6", "projectNumber": "25621943666", "lifecycleState": "ACTIVE", "createTime": "2016-10-22T16:57:36.066Z"},
    },
    {
        'resource_key': 'project7',
        'index': '94226340477',
        'resource_type': 'LOAD_PROJECTS',
        'resource_data': {"name": "project7", "parent": {"type": "organization", "id": "888888888888"}, "projectId": "project7", "projectNumber": "94226340477", "lifecycleState": "ACTIVE", "createTime": "2016-11-13T05:32:10.977Z"},
    }
]
# pylint: enable=line-too-long
