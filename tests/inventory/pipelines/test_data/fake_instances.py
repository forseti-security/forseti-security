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

'''Test instances data.'''

FAKE_API_RESPONSE1 = [{
    'kind': 'compute#instanceAggregatedList',
    'id': 'projects/project1/aggregated/instances',
    'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/aggregated/instances',
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
        'zones/us-central1-c': {
            'instances': [
                {
                    'kind': 'compute#instance',
                    'id': '6440513679799924564',
                    'creationTimestamp': '2017-05-26T22:08:11.094-07:00',
                    'name': 'iap-ig-79bj',
                    'tags': {
                        'items': [
                            'iap-tag'
                        ],
                        'fingerprint': 'gilEhx3hEXk='
                    },
                    'machineType': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/machineTypes/f1-micro',
                    'status': 'RUNNING',
                    'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
                    'canIpForward': False,
                    'networkInterfaces': [
                        {
                            'kind': 'compute#networkInterface',
                            'network': 'https://www.googleapis.com/compute/v1/projects/project1/global/networks/default',
                            'subnetwork': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default',
                            'networkIP': '10.128.0.2',
                            'name': 'nic0',
                            'accessConfigs': [
                                {
                                    'kind': 'compute#accessConfig',
                                    'type': 'ONE_TO_ONE_NAT',
                                    'name': 'External NAT',
                                    'natIP': '104.198.131.130'
                                }
                            ]
                        }
                    ],
                    'disks': [
                        {
                            'kind': 'compute#attachedDisk',
                            'type': 'PERSISTENT',
                            'mode': 'READ_WRITE',
                            'source': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/disks/iap-ig-79bj',
                            'deviceName': 'iap-it-1',
                            'index': 0,
                            'boot': True,
                            'autoDelete': True,
                            'licenses': [
                                'https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-8-jessie'
                            ],
                            'interface': 'SCSI'
                        }
                    ],
                    'metadata': {
                        'kind': 'compute#metadata',
                        'fingerprint': '3MpZMMvDTyo=',
                        'items': [
                            {
                                'key': 'instance-template',
                                'value': 'projects/600687511243/global/instanceTemplates/iap-it-1'
                            },
                            {
                                'key': 'created-by',
                                'value': 'projects/600687511243/zones/us-central1-c/instanceGroupManagers/iap-ig'
                            }
                        ]
                    },
                    'serviceAccounts': [
                        {
                            'email': '600687511243-compute@developer.gserviceaccount.com',
                            'scopes': [
                                'https://www.googleapis.com/auth/devstorage.read_only',
                                'https://www.googleapis.com/auth/logging.write',
                                'https://www.googleapis.com/auth/monitoring.write',
                                'https://www.googleapis.com/auth/servicecontrol',
                                'https://www.googleapis.com/auth/service.management.readonly',
                                'https://www.googleapis.com/auth/trace.append'
                            ]
                        }
                    ],
                    'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances/iap-ig-79bj',
                    'scheduling': {
                        'onHostMaintenance': 'MIGRATE',
                        'automaticRestart': True,
                        'preemptible': False
                    },
                    'cpuPlatform': 'Intel Haswell'
                }
            ]
        },
    },
}]

FAKE_API_RESPONSE2 = [{
    'kind': 'compute#instanceAggregatedList',
    'id': 'projects/project2/aggregated/instances',
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
    'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/aggregated/instances'
}]

FAKE_PROJECT_INSTANCES_MAP = {
    'project1': [
        {
            'kind': 'compute#instance',
            'id': '6440513679799924564',
            'creationTimestamp': '2017-05-26T22:08:11.094-07:00',
            'name': 'iap-ig-79bj',
            'tags': {
                'items': [
                    'iap-tag'
                ],
                'fingerprint': 'gilEhx3hEXk='
            },
            'machineType': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/machineTypes/f1-micro',
            'status': 'RUNNING',
            'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
            'canIpForward': False,
            'networkInterfaces': [
                {
                    'kind': 'compute#networkInterface',
                    'network': 'https://www.googleapis.com/compute/v1/projects/project1/global/networks/default',
                    'subnetwork': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default',
                    'networkIP': '10.128.0.2',
                    'name': 'nic0',
                    'accessConfigs': [
                        {
                            'kind': 'compute#accessConfig',
                            'type': 'ONE_TO_ONE_NAT',
                            'name': 'External NAT',
                            'natIP': '104.198.131.130'
                        }
                    ]
                }
            ],
            'disks': [
                {
                    'kind': 'compute#attachedDisk',
                    'type': 'PERSISTENT',
                    'mode': 'READ_WRITE',
                    'source': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/disks/iap-ig-79bj',
                    'deviceName': 'iap-it-1',
                    'index': 0,
                    'boot': True,
                    'autoDelete': True,
                    'licenses': [
                        'https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-8-jessie'
                    ],
                    'interface': 'SCSI'
                }
            ],
            'metadata': {
                'kind': 'compute#metadata',
                'fingerprint': '3MpZMMvDTyo=',
                'items': [
                    {
                        'key': 'instance-template',
                        'value': 'projects/600687511243/global/instanceTemplates/iap-it-1'
                    },
                    {
                        'key': 'created-by',
                        'value': 'projects/600687511243/zones/us-central1-c/instanceGroupManagers/iap-ig'
                    }
                ]
            },
            'serviceAccounts': [
                {
                    'email': '600687511243-compute@developer.gserviceaccount.com',
                    'scopes': [
                        'https://www.googleapis.com/auth/devstorage.read_only',
                        'https://www.googleapis.com/auth/logging.write',
                        'https://www.googleapis.com/auth/monitoring.write',
                        'https://www.googleapis.com/auth/servicecontrol',
                        'https://www.googleapis.com/auth/service.management.readonly',
                        'https://www.googleapis.com/auth/trace.append'
                    ]
                }
            ],
            'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/instances/iap-ig-79bj',
            'scheduling': {
                'onHostMaintenance': 'MIGRATE',
                'automaticRestart': True,
                'preemptible': False
            },
            'cpuPlatform': 'Intel Haswell'
        }
    ],
}

EXPECTED_LOADABLE_INSTANCES = [
    {
     'can_ip_forward': False,
     'cpu_platform': 'Intel Haswell',
     'creation_timestamp': '2017-05-26 22:08:11',
     'description': None,
     'disks': '[{"source": "https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/disks/iap-ig-79bj", "kind": "compute#attachedDisk", "mode": "READ_WRITE", "autoDelete": true, "deviceName": "iap-it-1", "licenses": ["https://www.googleapis.com/compute/v1/projects/debian-cloud/global/licenses/debian-8-jessie"], "index": 0, "interface": "SCSI", "boot": true, "type": "PERSISTENT"}]',
     'id': '6440513679799924564',
     'machine_type': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c/machineTypes/f1-micro',
     'metadata': '{"items": [{"value": "projects/600687511243/global/instanceTemplates/iap-it-1", "key": "instance-template"}, {"value": "projects/600687511243/zones/us-central1-c/instanceGroupManagers/iap-ig", "key": "created-by"}], "kind": "compute#metadata", "fingerprint": "3MpZMMvDTyo="}',
     'name': 'iap-ig-79bj',
     'network_interfaces': '[{"kind": "compute#networkInterface", "network": "https://www.googleapis.com/compute/v1/projects/project1/global/networks/default", "accessConfigs": [{"kind": "compute#accessConfig", "type": "ONE_TO_ONE_NAT", "name": "External NAT", "natIP": "104.198.131.130"}], "networkIP": "10.128.0.2", "subnetwork": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/subnetworks/default", "name": "nic0"}]',
     'project_id': 'project1',
     'scheduling': '{"automaticRestart": true, "preemptible": false, "onHostMaintenance": "MIGRATE"}',
     'service_accounts': '[{"scopes": ["https://www.googleapis.com/auth/devstorage.read_only", "https://www.googleapis.com/auth/logging.write", "https://www.googleapis.com/auth/monitoring.write", "https://www.googleapis.com/auth/servicecontrol", "https://www.googleapis.com/auth/service.management.readonly", "https://www.googleapis.com/auth/trace.append"], "email": "600687511243-compute@developer.gserviceaccount.com"}]',
     'status': 'RUNNING',
     'status_message': None,
     'tags': '{"items": ["iap-tag"], "fingerprint": "gilEhx3hEXk="}',
     'zone': 'https://www.googleapis.com/compute/v1/projects/project1/zones/us-central1-c',
    }
]
