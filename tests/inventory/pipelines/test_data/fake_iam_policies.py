#!/usr/bin/env python
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

"""Test IAM policies data."""

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

FAKE_FOLDER_IAM_POLICY_MAP = [{
    'folder_id': '12345',
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

FAKE_PROJECT_IAM_POLICY_MAP = [{
    'project_number': 555555555555,
    'iam_policy': {
        'bindings': [
            {'role': 'roles/editor', 'members': [
                'group:policyscanner-foo-group@henrychang.mygbiz.com',
                'serviceAccount:555555555555-compute@developer.gserviceaccount.com',
                'serviceAccount:555555555555@cloudbuild.gserviceaccount.com',
                'serviceAccount:555555555555@cloudservices.gserviceaccount.com',
                'serviceAccount:policyscanner-foo@appspot.gserviceaccount.com',
                'serviceAccount:service-555555555555@container-analysis.iam.gserviceaccount.com',
                'serviceAccount:service-555555555555@dataflow-service-producer-prod.iam.gserviceaccount.com',
                'user:foo@gmail.com',
                ]},
            {'role': 'roles/logging.configWriter',
             'members': ['serviceAccount:service-account-71@stackdriver-service.iam.gserviceaccount.com']},
            {'role': 'roles/logging.logWriter',
             'members': ['serviceAccount:service-account-71@stackdriver-service.iam.gserviceaccount.com']},
            {'role': 'roles/logging.privateLogViewer',
             'members': ['serviceAccount:service-account-71@stackdriver-service.iam.gserviceaccount.com']},
            {'role': 'roles/logging.viewer',
             'members': ['serviceAccount:service-account-71@stackdriver-service.iam.gserviceaccount.com']},
            {'role': 'roles/owner',
             'members': ['user:foo@henrychang.mygbiz.com']},
            ], 'version': 1, 'etag': 'BwVHfUJ0Apc='}
}]

EXPECTED_LOADABLE_ORG_IAM_POLICY = [
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

EXPECTED_LOADABLE_FOLDER_IAM_POLICY = [
    {'folder_id': '12345',
     'role': 'billing.creator',
     'member_domain': 'foo.com',
     'member_type': 'domain',
     'member_name': ''},
    {'folder_id': '12345',
     'role': 'browser',
     'member_domain': 'developer.gserviceaccount.com',
     'member_type': 'serviceAccount',
     'member_name': '55555-compute'},
    {'folder_id': '12345',
     'role': 'browser',
     'member_domain': 'developer.gserviceaccount.com',
     'member_type': 'serviceAccount',
     'member_name': '99999-compute'},
    {'folder_id': '12345',
     'role': 'resourcemanager.folderAdmin',
     'member_domain': 'foo.com',
     'member_type': 'user',
     'member_name': 'foo'},
    {'folder_id': '12345',
     'role': 'resourcemanager.organizationAdmin',
     'member_domain': 'foo.com',
     'member_type': 'user',
     'member_name': 'foo'},
    {'folder_id': '12345',
     'role': 'resourcemanager.organizationAdmin',
     'member_domain': 'foo.com',
     'member_type': 'user',
     'member_name': 'bar'},
    {'folder_id': '12345',
     'role': 'resourcemanager.projectCreator',
     'member_domain': 'foo.com',
     'member_type': 'domain', 'member_name': ''},
]

EXPECTED_LOADABLE_PROJECT_IAM_POLICY = [
    {'project_number': 555555555555,
     'member_domain': 'henrychang.mygbiz.com',
     'member_name': 'policyscanner-foo-group',
     'role': 'editor',
     'member_type': 'group'},
    {'project_number': 555555555555,
     'member_domain': 'developer.gserviceaccount.com',
     'member_name': '555555555555-compute',
     'role': 'editor',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'cloudbuild.gserviceaccount.com',
     'member_name': '555555555555',
     'role': 'editor',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'cloudservices.gserviceaccount.com',
     'member_name': '555555555555',
     'role': 'editor',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'appspot.gserviceaccount.com',
     'member_name': 'policyscanner-foo',
     'role': 'editor',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'container-analysis.iam.gserviceaccount.com',
     'member_name': 'service-555555555555',
     'role': 'editor',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'dataflow-service-producer-prod.iam.gserviceaccount.com',
     'member_name': 'service-555555555555',
     'role': 'editor',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'gmail.com',
     'member_name': 'foo',
     'role': 'editor',
     'member_type': 'user'},
    {'project_number': 555555555555,
     'member_domain': 'stackdriver-service.iam.gserviceaccount.com',
     'member_name': 'service-account-71',
     'role': 'logging.configWriter',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'stackdriver-service.iam.gserviceaccount.com',
     'member_name': 'service-account-71',
     'role': 'logging.logWriter',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'stackdriver-service.iam.gserviceaccount.com',
     'member_name': 'service-account-71',
     'role': 'logging.privateLogViewer',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'stackdriver-service.iam.gserviceaccount.com',
     'member_name': 'service-account-71',
     'role': 'logging.viewer',
     'member_type': 'serviceAccount'},
    {'project_number': 555555555555,
     'member_domain': 'henrychang.mygbiz.com',
     'member_name': 'foo',
     'role': 'owner',
     'member_type': 'user'}
]
