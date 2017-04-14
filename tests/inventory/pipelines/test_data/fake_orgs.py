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

FAKE_ORGS = [
    {
        'organizations': [
            {
                'name': 'organizations/111111111111',
                'displayName': 'Organization1',
                'lifecycleState': 'ACTIVE',
                'creationTime': '2016-10-22T16:57:36.096Z'
            },
            {
                'name': 'organizations/222222222222',
                'displayName': 'Organization2',
                'lifecycleState': 'ACTIVE',
                'creationTime': '2016-11-13T05:32:10.930Z'
            },
            {
                'name': 'organizations/333333333333',
                'displayName': 'Organization3',
                'lifecycleState': 'ACTIVE',
                'creationTime': '2016-11-13T05:32:49.377Z'
            },
        ]
    },
    {
        'organizations': [
            {
                'name': 'organizations/444444444444',
                'displayName': 'Organization4',
                'lifecycleState': 'ACTIVE',
                'creationTime': '2016-10-22T16:57:36.066Z'
            },
            {
                'name': 'organizations/555555555555',
                'displayName': 'Organization5',
                'lifecycleState': 'ACTIVE',
                'creationTime': '2016-11-13T05:32:10.977Z'
            }
        ]
    }
]


EXPECTED_LOADABLE_ORGS = [
    {
        'org_id': '111111111111',
        'name': 'organizations/111111111111',
        'display_name': 'Organization1',
        'lifecycle_state': 'ACTIVE',
        'creation_time': '2016-10-22 16:57:36',
        'raw_org': ''
    },
    {
        'org_id': '222222222222',
        'name': 'organizations/222222222222',
        'display_name': 'Organization2',
        'lifecycle_state': 'ACTIVE',
        'creation_time': '2016-11-13 05:32:10',
        'raw_org': ''
    },
    {
        'org_id': '333333333333',
        'name': 'organizations/333333333333',
        'display_name': 'Organization3',
        'lifecycle_state': 'ACTIVE',
        'creation_time': '2016-11-13 05:32:49',
        'raw_org': ''
    },
    {
        'org_id': '444444444444',
        'name': 'organizations/444444444444',
        'display_name': 'Organization4',
        'lifecycle_state': 'ACTIVE',
        'creation_time': '2016-10-22 16:57:36',
        'raw_org': ''
    },
    {
        'org_id': '555555555555',
        'name': 'organizations/555555555555',
        'display_name': 'Organization5',
        'lifecycle_state': 'ACTIVE',
        'creation_time': '2016-11-13 05:32:10',
        'raw_org': ''
    }
]
