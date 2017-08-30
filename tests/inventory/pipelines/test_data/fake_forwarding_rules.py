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

"""Test forwarding rules data."""

from google.cloud.security.common.util import parser


FAKE_FORWARDING_RULE1 = {
    "kind": "compute#forwardingRule",
    "description": "",
    "IPAddress": "10.10.10.1",
    "region": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1",
    "loadBalancingScheme": "EXTERNAL",
    "target": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/targetPools/project1-pool",
    "portRange": "80-80",
    "IPProtocol": "TCP",
    "creationTimestamp": "2017-05-05T12:00:01.000-07:00",
    "id": "111111111111",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/forwardingRules/project1-rule",
    "name": "project1-rule"
}

FAKE_FORWARDING_RULE2 = {
    "kind": "compute#forwardingRule",
    "description": "",
    "IPAddress": "10.10.10.2",
    "region": "https://www.googleapis.com/compute/v1/projects/project2/regions/us-central1",
    "loadBalancingScheme": "EXTERNAL",
    "target": "https://www.googleapis.com/compute/v1/projects/project2/regions/us-central1/targetPools/project2-pool",
    "portRange": "80-80",
    "IPProtocol": "TCP",
    "creationTimestamp": "2017-05-05T12:00:01.000-07:00",
    "id": "222222222222",
    "selfLink": "https://www.googleapis.com/compute/v1/projects/project2/regions/us-central1/forwardingRules/project2-rule",
    "name": "project2-rule"
}


FAKE_API_RESPONSE1 = [FAKE_FORWARDING_RULE1]

FAKE_API_RESPONSE2 = [FAKE_FORWARDING_RULE2]

FAKE_PROJECT_FWD_RULES_MAP = {
    'project1': [FAKE_FORWARDING_RULE1],
    'project2': [FAKE_FORWARDING_RULE2],
}

EXPECTED_LOADABLE_FWD_RULES = [
    {'project_id': 'project1',
     'description': '',
     'ip_address': '10.10.10.1',
     'region': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1',
     'backend_service': None,
     'load_balancing_scheme': 'EXTERNAL',
     'target': 'https://www.googleapis.com/compute/v1/projects/project1/regions/us-central1/targetPools/project1-pool',
     'port_range': '80-80',
     'ports': '[]',
     'ip_protocol': 'TCP',
     'creation_timestamp': '2017-05-05 12:00:01',
     'id': '111111111111',
     'name': 'project1-rule',
     'network': None,
     'subnetwork': None,
     'raw_forwarding_rule': parser.json_stringify(FAKE_FORWARDING_RULE1),
    },
    {'project_id': 'project2',
     'description': '',
     'ip_address': '10.10.10.2',
     'region': 'https://www.googleapis.com/compute/v1/projects/project2/regions/us-central1',
     'backend_service': None,
     'load_balancing_scheme': 'EXTERNAL',
     'target': 'https://www.googleapis.com/compute/v1/projects/project2/regions/us-central1/targetPools/project2-pool',
     'port_range': '80-80',
     'ports': '[]',
     'ip_protocol': 'TCP',
     'creation_timestamp': '2017-05-05 12:00:01',
     'id': '222222222222',
     'name': 'project2-rule',
     'network': None,
     'subnetwork': None,
     'raw_forwarding_rule': parser.json_stringify(FAKE_FORWARDING_RULE2),
    },
]
