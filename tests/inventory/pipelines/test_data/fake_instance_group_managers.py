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

'''Test instance group managers data.'''

FAKE_API_RESPONSE1 = [{
    "kind": "compute#instanceGroupManagerAggregatedList",
    "id": "projects/project1/aggregated/instanceGroupManagers",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/instanceGroupManagers",
    "items": {
        "regions/us-central1": {
            "warning": {
                "code": "NO_RESULTS_ON_PAGE",
                "message": "There are no results for scope 'regions/us-central1' on this page.",
                "data": [
                    {
                        "key": "scope",
                        "value": "regions/us-central1"
                    }
                ]
            }
        },
        "zones/us-central1-c": {
            "instanceGroupManagers": [
                {
                    "kind": "compute#instanceGroupManager",
                    "id": "1532459550555580553",
                    "creationTimestamp": "2017-05-26T13:56:06.149-07:00",
                    "name": "iap-ig",
                    "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
                    "instanceTemplate": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1",
                    "instanceGroup": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig",
                    "baseInstanceName": "iap-ig",
                    "fingerprint": "OYowLtDCpv8=",
                    "currentActions": {
                        "none": 1,
                        "creating": 0,
                        "creatingWithoutRetries": 0,
                        "recreating": 0,
                        "deleting": 0,
                        "abandoning": 0,
                        "restarting": 0,
                        "refreshing": 0
                    },
                    "targetSize": 1,
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroupManagers/iap-ig",
                    "namedPorts": [
                        {
                            "name": "http",
                            "port": 80
                        }
                    ]
                }
            ]
        },
     }
}]

FAKE_API_RESPONSE2 = [{
    'kind': 'compute#instanceGroupManagerAggregatedList',
    'id': 'projects/project2/aggregated/instanceGroupManagers',
    'items': {
        'zones/us-central1-a': {
            'warning': {
                'code': 'NO_RESULTS_ON_PAGE',
                'message': 'There are no results for scope \'zones/us-central1-a\' on this page.',
                'data': [
                    {
                        'key': 'scope',
                        'value': 'zones/us-central1-a'
                    }
                ]
            }
        },
    },
    'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/aggregated/instanceGroupManagers'
}]

FAKE_PROJECT_INSTANCE_GROUP_MANAGERS_MAP = {
    'project1': [{
        'creationTimestamp': '2017-05-26T13:56:06.149-07:00',
        'currentActions': {'none': 1,
                           'recreating': 0,
                           'creating': 0,
                           'refreshing': 0,
                           'abandoning': 0,
                           'deleting': 0,
                           'creatingWithoutRetries': 0,
                           'restarting': 0
        },
        'baseInstanceName': 'iap-ig',
        'fingerprint': 'OYowLtDCpv8=',
        'id': '1532459550555580553',
        'instanceGroup': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig',
        'instanceTemplate': 'https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1',
        'kind': 'compute#instanceGroupManager',
        'name': 'iap-ig',
        'namedPorts': [
            {'name': 'http', 'port': 80},
        ],
        'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroupManagers/iap-ig',
        'targetSize': 1,
        'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
    }],
}

EXPECTED_LOADABLE_INSTANCE_GROUP_MANAGERS = [
    {'base_instance_name': 'iap-ig',
     'creation_timestamp': '2017-05-26 13:56:06',
     'current_actions': (
         '{"none": 1, "restarting": 0, "recreating": 0, "creating": 0, '
         '"abandoning": 0, "deleting": 0, "creatingWithoutRetries": 0, '
         '"refreshing": 0}'),
     'description': None,
     'id': '1532459550555580553',
     'instance_group': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig',
     'instance_template': 'https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1',
     'name': 'iap-ig',
     'named_ports': '[{"name": "http", "port": 80}]',
     'project_id': 'project1',
     'region': None,
     'target_pools': '[]',
     'target_size': 1,
     'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
     }
]
