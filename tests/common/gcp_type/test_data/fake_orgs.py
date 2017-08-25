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

"""Fake organization data."""

FAKE_ORGS_DB_ROWS = [
    {'org_id': '111111111111',
     'name': 'organizations/111111111111',
     'display_name': 'Organization1',
     'lifecycle_state': 'ACTIVE',
     'creation_timestamp': '2015-09-09 00:01:01'},
    {'org_id': '222222222222',
     'name': 'organizations/222222222222',
     'display_name': 'Organization2',
     'lifecycle_state': 'ACTIVE',
     'creation_timesetamp': '2015-10-10 00:02:02'},
]

FAKE_ORGS_RESPONSE = {
    'organizations': [
        {
          'name': 'organizations/1111111111',
          'display_name': 'Organization1',
          'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'organizations/2222222222',
            'display_name': 'Organization2',
            'lifecycleState': 'ACTIVE',
        },
        {
            'name': 'organizations/3333333333',
            'display_name': 'Organization3',
            'lifecycleState': 'ACTIVE',
        }
    ]
}

EXPECTED_FAKE_ORGS_FROM_API = [FAKE_ORGS_RESPONSE]

FAKE_ORGS_OK_IAM_DB_ROWS = [
    {'org_id': '1111111111',
     'iam_policy': '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'},
    {'org_id': '2222222222',
     'iam_policy': '{"bindings": [{"role": "roles/viewer", "members": ["user:d@e.f"]}]}'},
]

FAKE_ORGS_BAD_IAM_DB_ROWS = [
    {'org_id': '1111111111',
     'iam_policy': '{"bindings": [{"role": "roles/viewer", "members": ["user:a@b.c"]}]}'},
    {'org_id': '2222222222',
     'iam_policy': ''},
]
