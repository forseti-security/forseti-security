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

'''Test instance group templates data.'''

FAKE_API_RESPONSE1 = [{
    "kind": "compute#instanceTemplateList",
    "id": "projects/project1/global/instanceTemplates",
    "items": [
        {
            "kind": "compute#instanceTemplate",
            "id": "599361064932783991",
            "creationTimestamp": "2017-05-26T22:07:36.275-07:00",
            "name": "iap-it-1",
            "description": "",
            "properties": {
                "tags": {
                    "items": [
                        "iap-tag"
                    ]
                },
                "machineType": "f1-micro",
                "canIpForward": False,
                "networkInterfaces": [
                    {
                        "kind": "compute#networkInterface",
                        "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default",
                        "accessConfigs": [
                            {
                                "kind": "compute#accessConfig",
                                "type": "ONE_TO_ONE_NAT",
                                "name": "External NAT"
                            }
                        ]
                    }
                ],
                "disks": [
                    {
                        "kind": "compute#attachedDisk",
                        "type": "PERSISTENT",
                        "mode": "READ_WRITE",
                        "deviceName": "iap-it-1",
                        "boot": True,
                        "initializeParams": {
                            "sourceImage": "projects/debian-cloud/global/images/debian-8-jessie-v20170523",
                            "diskSizeGb": "10",
                            "diskType": "pd-standard"
                        },
                        "autoDelete": True
                    }
                ],
                "metadata": {
                    "kind": "compute#metadata",
                    "fingerprint": "Ab2_F_dLE3A="
                },
                "serviceAccounts": [
                    {
                        "email": "600687511243-compute@developer.gserviceaccount.com",
                        "scopes": [
                            "https://www.googleapis.com/auth/devstorage.read_only",
                            "https://www.googleapis.com/auth/logging.write",
                            "https://www.googleapis.com/auth/monitoring.write",
                            "https://www.googleapis.com/auth/servicecontrol",
                            "https://www.googleapis.com/auth/service.management.readonly",
                            "https://www.googleapis.com/auth/trace.append"
                        ]
                    }
                ],
                "scheduling": {
                    "onHostMaintenance": "MIGRATE",
                    "automaticRestart": True,
                    "preemptible": False
                }
            },
            "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1"
        }
    ],
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates"
}]

FAKE_API_RESPONSE2 = [{
    "kind": "compute#instanceTemplateList",
    "id": "projects/project2/global/instanceTemplates",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project2/global/instanceTemplates"
}]

FAKE_PROJECT_INSTANCE_TEMPLATES_MAP = {
    'project1': [{
        'kind': 'compute#instanceTemplate',
        'description': '',
        'properties': {'machineType': 'f1-micro',
                       'tags': {'items': ['iap-tag']},
                       'scheduling': {'automaticRestart': True,
                                      'preemptible': False,
                                      'onHostMaintenance': 'MIGRATE'},
                       'canIpForward': False,
                       'serviceAccounts': [{'scopes':
                                            ['https://www.googleapis.com/auth/devstorage.read_only',
                                             'https://www.googleapis.com/auth/logging.write',
                                             'https://www.googleapis.com/auth/monitoring.write',
                                             'https://www.googleapis.com/auth/servicecontrol',
                                             'https://www.googleapis.com/auth/service.management.readonly',
                                             'https://www.googleapis.com/auth/trace.append'],
                                            'email': '600687511243-compute@developer.gserviceaccount.com'}],
                       'disks': [{'deviceName': 'iap-it-1',
                                  'kind': 'compute#attachedDisk',
                                  'initializeParams': {'diskSizeGb': '10',
                                                       'sourceImage': 'projects/debian-cloud/global/images/debian-8-jessie-v20170523',
                                                       'diskType': 'pd-standard'},
                                  'autoDelete': True,
                                  'boot': True,
                                  'mode': 'READ_WRITE',
                                  'type': 'PERSISTENT'}],
                       'metadata': {'kind': 'compute#metadata',
                                    'fingerprint': 'Ab2_F_dLE3A='},
                       'networkInterfaces': [{'kind':
                                              'compute#networkInterface',
                                              'accessConfigs': [{'kind': 'compute#accessConfig',
                                                                 'type': 'ONE_TO_ONE_NAT',
                                                                 'name': 'External NAT'}],
                                              'network': 'https://www.googleapis.com/compute/v1/projects/project1/global/networks/default'}]},
        'creationTimestamp': '2017-05-26T22:07:36.275-07:00',
        'id': '599361064932783991',
        'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/global/instanceTemplates/iap-it-1',
        'name': 'iap-it-1'
    }],
}

EXPECTED_LOADABLE_INSTANCE_TEMPLATES = [
    {'creation_timestamp': '2017-05-26 22:07:36',
     'description': '',
     'id': '599361064932783991',
     'name': 'iap-it-1',
     'project_id': 'project1',
     'properties': ('{"machineType": "f1-micro", "tags": {"items": ["iap-tag"]}, '
                    '"scheduling": {"automaticRestart": true, "preemptible": false, '
                    '"onHostMaintenance": "MIGRATE"}, "canIpForward": false, '
                    '"serviceAccounts": [{"scopes": '
                    '["https://www.googleapis.com/auth/devstorage.read_only", '
                    '"https://www.googleapis.com/auth/logging.write", '
                    '"https://www.googleapis.com/auth/monitoring.write", '
                    '"https://www.googleapis.com/auth/servicecontrol", '
                    '"https://www.googleapis.com/auth/service.management.readonly", '
                    '"https://www.googleapis.com/auth/trace.append"], '
                    '"email": "600687511243-compute@developer.gserviceaccount.com"}], '
                    '"disks": [{"deviceName": "iap-it-1", "kind": "compute#attachedDisk", '
                    '"initializeParams": {"diskSizeGb": "10", "sourceImage": '
                    '"projects/debian-cloud/global/images/debian-8-jessie-v20170523", '
                    '"diskType": "pd-standard"}, "autoDelete": true, "boot": true, '
                    '"mode": "READ_WRITE", "type": "PERSISTENT"}], '
                    '"networkInterfaces": [{"kind": "compute#networkInterface", '
                    '"accessConfigs": [{"kind": "compute#accessConfig", "type": '
                    '"ONE_TO_ONE_NAT", "name": "External NAT"}], "network": '
                    '"https://www.googleapis.com/compute/v1/projects/project1/global/networks/default"}], '
                    '"metadata": {"kind": "compute#metadata", "fingerprint": "Ab2_F_dLE3A="}}')
    }
]
