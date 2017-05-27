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
    "kind": "compute#instanceGroupAggregatedList",
    "id": "projects/project1/aggregated/instanceGroups",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/instanceGroups",
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
            "instanceGroups": [
                {
                    "kind": "compute#instanceGroup",
                    "id": "1532459550555580553",
                    "creationTimestamp": "2017-05-26T13:56:06.149-07:00",
                    "name": "iap-ig",
                    "description": "This instance group is controlled by Instance Group Manager 'iap-ig'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
                    "namedPorts": [
                        {
                            "name": "http",
                            "port": 80
                        }
                    ],
                    "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
                    "fingerprint": "l9ccw0jwP90=",
                    "zone": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c",
                    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig",
                    "size": 1,
                    "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default"
                }
            ]
        },
     }
}]

FAKE_API_RESPONSE2 = [{
    'kind': 'compute#instanceGroupAggregatedList',
    'id': 'projects/project2/aggregated/instanceGroups',
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
    'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/aggregated/instanceGroups'
}]

FAKE_PROJECT_INSTANCE_GROUPS_MAP = {
    'project1': [{
        'creationTimestamp': '2017-05-26T13:56:06.149-07:00',
        'description': ("This instance group is controlled by Instance Group "
                        "Manager 'iap-ig'. To modify instances in this group, "
                        "use the Instance Group Manager API: "
                        "https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers"),
        'fingerprint': 'l9ccw0jwP90=',
        'id': '1532459550555580553',
        'kind': 'compute#instanceGroup',
        'name': 'iap-ig',
        'namedPorts': [{'name': 'http', 'port': 80}],
        'network': 'https://www.googleapis.com/compute/v1/projects/project1/global/networks/default',
        'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instanceGroups/iap-ig',
        'size': 1,
        'subnetwork': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default',
        'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
    }],
}

EXPECTED_LOADABLE_INSTANCE_GROUPS = [
    {'creation_timestamp': '2017-05-26 13:56:06',
     'description': "This instance group is controlled by Instance Group Manager 'iap-ig'. To modify instances in this group, use the Instance Group Manager API: https://cloud.google.com/compute/docs/reference/latest/instanceGroupManagers",
     'id': '1532459550555580553',
     'name': 'iap-ig',
     'named_ports': '[{"name": "http", "port": 80}]',
     'network': 'https://www.googleapis.com/compute/v1/projects/project1/global/networks/default',
     'project_id': 'project1',
     'region': None,
     'size': 1,
     'subnetwork': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default',
     'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
    }
]
