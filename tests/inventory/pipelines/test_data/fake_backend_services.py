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

"""Test backend services data."""

FAKE_API_RESPONSE1 = [
    {
        "kind": "compute#backendService",
        "id": "3072061062494750400",
        "creationTimestamp": "2017-04-03T14:01:35.687-07:00",
        "name": "bs-1",
        "description": "bs-1-desc",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/backendServices/bs-1",
        "backends": [
            {
                "group": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/bs-1-ig-1",
                "balancingMode": "UTILIZATION",
                "capacityScaler": 1.0
            }
        ],
        "healthChecks": [
            "https://www.googleapis.com/compute/v1/projects/project1/global/httpsHealthChecks/hc-1"
        ],
        "timeoutSec": 3610,
        "port": 8443,
        "protocol": "HTTPS",
        "portName": "https",
        "enableCDN": False,
        "sessionAffinity": "NONE",
        "affinityCookieTtlSec": 0,
        "loadBalancingScheme": "EXTERNAL",
        "connectionDraining": {
            "drainingTimeoutSec": 0
        }
    },
]

FAKE_API_RESPONSE2 = [
    {
        "kind": "compute#backendService",
        "id": "6071052922189792661",
        "creationTimestamp": "2017-05-12T11:14:18.559-07:00",
        "name": "iap-bs",
        "description": "",
        "selfLink": "https://www.googleapis.com/compute/v1/projects/project2/global/backendServices/iap-bs",
        "backends": [
            {
                "description": "",
                "group": "https://www.googleapis.com/compute/v1/projects/project2/zones/us-east1-c/instanceGroups/instance-group-1",
                "balancingMode": "UTILIZATION",
                "maxUtilization": 0.8,
                "capacityScaler": 1.0
            }
        ],
        "healthChecks": [
            "https://www.googleapis.com/compute/v1/projects/project2/global/healthChecks/iap-hc"
        ],
        "timeoutSec": 30,
        "port": 80,
        "protocol": "HTTP",
        "portName": "http",
        "enableCDN": False,
        "sessionAffinity": "NONE",
        "affinityCookieTtlSec": 0,
        "loadBalancingScheme": "EXTERNAL",
        "connectionDraining": {
            "drainingTimeoutSec": 300
        },
        "iap": {
            "enabled": True,
            "oauth2ClientId": "foo",
            "oauth2ClientSecretSha256": "bar"
        }
    },
]

FAKE_PROJECT_BACKEND_SERVICES_MAP = {
    'project1': [
        {'kind': 'compute#backendService',
         'id': '3072061062494750400',
         'creationTimestamp': '2017-04-03T14:01:35.687-07:00',
         'name': 'bs-1',
         'description': 'bs-1-desc',
         'selfLink': 'https://www.googleapis.com/compute/v1/projects/project1/global/backendServices/bs-1',
         'backends': [
             {
                 'group': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/bs-1-ig-1',
                 'balancingMode': 'UTILIZATION',
                 'capacityScaler': 1.0
             }
         ],
         'healthChecks': [
             'https://www.googleapis.com/compute/v1/projects/project1/global/httpsHealthChecks/hc-1'
         ],
         'timeoutSec': 3610,
         'port': 8443,
         'protocol': 'HTTPS',
         'portName': 'https',
         'enableCDN': False,
         'sessionAffinity': 'NONE',
         'affinityCookieTtlSec': 0,
         'loadBalancingScheme': 'EXTERNAL',
         'connectionDraining': {
             'drainingTimeoutSec': 0
         },
        },
    ],
    'project2': [
        {'kind': 'compute#backendService',
         'id': '6071052922189792661',
         'creationTimestamp': '2017-05-12T11:14:18.559-07:00',
         'name': 'iap-bs',
         'description': '',
         'selfLink': 'https://www.googleapis.com/compute/v1/projects/project2/global/backendServices/iap-bs',
         'backends': [
             {
                 'description': '',
                 'group': 'https://www.googleapis.com/compute/v1/projects/project2/zones/us-east1-c/instanceGroups/instance-group-1',
                 'balancingMode': 'UTILIZATION',
                 'maxUtilization': 0.8,
                 'capacityScaler': 1.0
             }
         ],
         'healthChecks': [
             'https://www.googleapis.com/compute/v1/projects/project2/global/healthChecks/iap-hc'
         ],
         'timeoutSec': 30,
         'port': 80,
         'protocol': 'HTTP',
         'portName': 'http',
         'enableCDN': False,
         'sessionAffinity': 'NONE',
         'affinityCookieTtlSec': 0,
         'loadBalancingScheme': 'EXTERNAL',
         'connectionDraining': {
             'drainingTimeoutSec': 300
         },
         'iap': {
             'enabled': True,
             'oauth2ClientId': 'foo',
             'oauth2ClientSecretSha256': 'bar'
         }
        },
    ],
}

EXPECTED_LOADABLE_BACKEND_SERVICES = [
    {'affinity_cookie_ttl_sec': 0,
     'backends': '[{"capacityScaler": 1.0, "group": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/bs-1-ig-1", "balancingMode": "UTILIZATION"}]',
     'cdn_policy': '{}',
     'connection_draining': '{"drainingTimeoutSec": 0}',
     'creation_timestamp': '2017-04-03 14:01:35',
     'description': 'bs-1-desc',
     'enable_cdn': False,
     'health_checks': '["https://www.googleapis.com/compute/v1/projects/project1/global/httpsHealthChecks/hc-1"]',
     'iap': '{}',
     'id': '3072061062494750400',
     'load_balancing_scheme': 'EXTERNAL',
     'name': 'bs-1',
     'port': 8443,
     'port_name': 'https',
     'project_id': 'project1',
     'protocol': 'HTTPS',
     'region': None,
     'session_affinity': 'NONE',
     'timeout_sec': 3610,
     'raw_backend_service': '{"connectionDraining": {"drainingTimeoutSec": 0}, "kind": "compute#backendService", "protocol": "HTTPS", "name": "bs-1", "timeoutSec": 3610, "enableCDN": false, "loadBalancingScheme": "EXTERNAL", "affinityCookieTtlSec": 0, "port": 8443, "backends": [{"capacityScaler": 1.0, "group": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/instanceGroups/bs-1-ig-1", "balancingMode": "UTILIZATION"}], "portName": "https", "healthChecks": ["https://www.googleapis.com/compute/v1/projects/project1/global/httpsHealthChecks/hc-1"], "sessionAffinity": "NONE", "creationTimestamp": "2017-04-03T14:01:35.687-07:00", "id": "3072061062494750400", "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/global/backendServices/bs-1", "description": "bs-1-desc"}'},
    {'affinity_cookie_ttl_sec': 0,
     'backends': '[{"maxUtilization": 0.8, "capacityScaler": 1.0, "group": "https://www.googleapis.com/compute/v1/projects/project2/zones/us-east1-c/instanceGroups/instance-group-1", "description": "", "balancingMode": "UTILIZATION"}]',
     'cdn_policy': '{}',
     'connection_draining': '{"drainingTimeoutSec": 300}',
     'creation_timestamp': '2017-05-12 11:14:18',
     'description': '',
     'enable_cdn': False,
     'health_checks': '["https://www.googleapis.com/compute/v1/projects/project2/global/healthChecks/iap-hc"]',
     'iap': '{"oauth2ClientId": "foo", "enabled": true, "oauth2ClientSecretSha256": "bar"}',
     'id': '6071052922189792661',
     'load_balancing_scheme': 'EXTERNAL',
     'name': 'iap-bs',
     'port': 80,
     'port_name': 'http',
     'project_id': 'project2',
     'protocol': 'HTTP',
     'region': None,
     'session_affinity': 'NONE',
     'timeout_sec': 30,
     'raw_backend_service': '{"connectionDraining": {"drainingTimeoutSec": 300}, "kind": "compute#backendService", "protocol": "HTTP", "name": "iap-bs", "timeoutSec": 30, "enableCDN": false, "loadBalancingScheme": "EXTERNAL", "affinityCookieTtlSec": 0, "port": 80, "backends": [{"maxUtilization": 0.8, "capacityScaler": 1.0, "group": "https://www.googleapis.com/compute/v1/projects/project2/zones/us-east1-c/instanceGroups/instance-group-1", "description": "", "balancingMode": "UTILIZATION"}], "iap": {"oauth2ClientId": "foo", "enabled": true, "oauth2ClientSecretSha256": "bar"}, "portName": "http", "healthChecks": ["https://www.googleapis.com/compute/v1/projects/project2/global/healthChecks/iap-hc"], "sessionAffinity": "NONE", "creationTimestamp": "2017-05-12T11:14:18.559-07:00", "id": "6071052922189792661", "selfLink": "https://www.googleapis.com/compute/v1/projects/project2/global/backendServices/iap-bs", "description": ""}',},
]
