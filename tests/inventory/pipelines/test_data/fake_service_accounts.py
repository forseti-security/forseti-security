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

"""Fake Service Account data."""

import copy

from google.cloud.security.common.util import parser

FAKE_PROJECT_SERVICE_ACCOUNTS_MAP = {
    'project1': [
        {
            'name': 'service-account@example.test',
            'email': 'service-account@example.test',
            'oauth2ClientId': '12345',
        },
    ]
}

FAKE_PROJECT_SERVICE_ACCOUNTS_MAP_WITH_KEYS = {
    'project1': [
        {
            'name': 'service-account@example.test',
            'email': 'service-account@example.test',
            'oauth2ClientId': '12345',
            'keys': []
        },
    ]
}

FAKE_SERVICE_ACCOUNT_KEYS = {
    'service-account@example.test': {
        'keys': [],
    }
}

EXPECTED_LOADABLE_SERVICE_ACCOUNTS = [
    {
        'project_id': 'project1',
        'name': 'service-account@example.test',
        'email': 'service-account@example.test',
        'oauth2_client_id': '12345',
        'account_keys': parser.json_stringify(
            FAKE_SERVICE_ACCOUNT_KEYS['service-account@example.test']['keys']),
        'raw_service_account': parser.json_stringify(
            FAKE_PROJECT_SERVICE_ACCOUNTS_MAP_WITH_KEYS['project1'][0]),
    }
]
