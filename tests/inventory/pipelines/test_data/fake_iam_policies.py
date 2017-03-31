#!/usr/bin/env python
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


FAKE_ORG_IAM_POLICY_MAP = [{
    'org_id': 666666,
    'iam_policy': {
        'bindings': [
            {'role': 'roles/billing.creator', 'members': [
                'domain:foo.com'
            ]},
            {'role': 'roles/browser', 'members': [
                'serviceAccount:55555-compute@developer.gserviceaccount.com',
                'serviceAccount:99999-compute@developer.gserviceaccount.com',
                ]},
            {'role': 'roles/resourcemanager.folderAdmin',
             'members': ['user:foo@foo.com']},
            {'role': 'roles/resourcemanager.organizationAdmin', 'members': [
                'user:foo@foo.com',
                'user:bar@foo.com'
                ]},
            {'role': 'roles/resourcemanager.projectCreator', 'members': ['domain:foo.com']}
            ], 'etag': 'BwVHXBMqO0k='}
}]

EXPECTED_FLATTENED_ORG_IAM_POLICY = [
    {'org_id': 666666,
     'role': 'billing.creator',
     'member_domain': 'foo.com',
     'member_type': 'domain',
     'member_name': ''},
    {'org_id': 666666,
     'role': 'browser',
     'member_domain': 'developer.gserviceaccount.com',
     'member_type': 'serviceAccount',
     'member_name': '55555-compute'},
    {'org_id': 666666,
     'role': 'browser',
     'member_domain': 'developer.gserviceaccount.com',
     'member_type': 'serviceAccount',
     'member_name': '99999-compute'},
    {'org_id': 666666,
     'role': 'resourcemanager.folderAdmin',
     'member_domain': 'foo.com',
     'member_type': 'user',
     'member_name': 'foo'},
    {'org_id': 666666,
     'role': 'resourcemanager.organizationAdmin',
     'member_domain': 'foo.com',
     'member_type': 'user',
     'member_name': 'foo'},
    {'org_id': 666666,
     'role': 'resourcemanager.organizationAdmin',
     'member_domain': 'foo.com',
     'member_type': 'user',
     'member_name': 'bar'},
    {'org_id': 666666,
     'role': 'resourcemanager.projectCreator',
     'member_domain': 'foo.com',
     'member_type': 'domain', 'member_name': ''},
]
