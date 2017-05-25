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

"""Test backend services data."""

FAKE_API_RESPONSE1 = [{
    "items": {
        "regions/europe-west1": {
            "warning": {
                "code": "NO_RESULTS_ON_PAGE",
                "message": "There are no results for scope 'regions/europe-west1' on this page.",
                "data": [
                    {
                        "key": "scope",
                        "value": "regions/europe-west1"
                    }
                ]
            }
        },
        "global": {
            "backendServices": [
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
            ],
        },
    },
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/aggregated/backendServices",
    "kind": "compute#backendServiceAggregatedList",
    "id": "projects/project1/aggregated/backendServices",
}]

FAKE_API_RESPONSE2 = [{
    "items": {
        "regions/europe-west1": {
            "warning": {
                "code": "NO_RESULTS_ON_PAGE",
                "message": "There are no results for scope 'regions/europe-west1' on this page.",
                "data": [
                    {
                        "key": "scope",
                        "value": "regions/europe-west1"
                    }
                ]
            }
        },
        "global": {
            "backendServices": [
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
            ],
        },
    },
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project2/aggregated/backendServices",
    "kind": "compute#backendServiceAggregatedList",
    "id": "projects/project2/aggregated/backendServices",
}]

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
     'timeout_sec': 3610},
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
     'timeout_sec': 30},
]
