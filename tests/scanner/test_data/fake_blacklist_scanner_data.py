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

"""Fake instance data."""

from google.cloud.forseti.scanner.audit import blacklist_rules_engine

FAKE_BLACKLIST_SOURCE_1 = '\n'.join(['#sdfsdf',
                                     '1.2.3.4',
                                     '#127.0.0.1',
                                     '5.6.7.0/24',
                                     '#104.199.142.52',
                                     '#104.199.142.52/0'])


FAKE_BLACKLIST_SOURCE_2 = '\n'.join(['5.5.5.5'])


EXPECTED_BLACKLIST_1 = [['1.2.3.4'], ['5.6.7.0/24']]

INSTANCE_DATA = [
    {
        'full_name': 'fake_full_name111',
        'network_interfaces': [
            {"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/default", "networkIP": "1.2.0.2", "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/us-central1/subnetworks/default", "fingerprint": "x=", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT"}]}],
    },
    {
        'full_name': 'fake_full_name222',
        'network_interfaces': [
            {"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/default", "networkIP": "1.2.0.2", "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/default", "fingerprint": "y=", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "1.2.3.4"}]},
            {"kind": "compute#networkInterface", "name": "nic1", "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/testnetwork", "networkIP": "1.1.0.2", "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/sadadasd", "fingerprint": "z=", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "5.6.7.8"}]}]
    },
    {
        'full_name': 'fake_full_name333',
        'network_interfaces': [
            {"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/default", "networkIP": "1.2.0.3", "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/default", "fingerprint": "d=", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "9.10.11.12"}]},
            {"kind": "compute#networkInterface", "name": "nic1", "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/testnetwork", "networkIP": "1.1.0.3", "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/sadadasd", "fingerprint": "c=", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "5.5.5.5"}]}]
    },
    {
        'full_name': 'fake_full_name444',
        'network_interfaces':  [
            {"kind": "compute#networkInterface", "name": "nic0", "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/default", "networkIP": "1.2.0.2", "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/us-east4/subnetworks/default", "fingerprint": "v=", "accessConfigs": [{"kind": "compute#accessConfig", "name": "External NAT", "type": "ONE_TO_ONE_NAT", "natIP": "5.6.7.254"}]}]
    }
]

RuleViolation = blacklist_rules_engine.Rule.RuleViolation

EXPECTED_VIOLATIONS = [
    [],
    [RuleViolation(resource_type='instance', resource_name='dev-project', full_name='fake_full_name222', rule_blacklist='ET', rule_name='ET', rule_index=0, violation_type='BLACKLIST_VIOLATION', project='dev-project', network='default', ip='1.2.3.4', resource_data='{\n  "accessConfigs": [\n    {\n      "kind": "compute#accessConfig", \n      "name": "External NAT", \n      "natIP": "1.2.3.4", \n      "type": "ONE_TO_ONE_NAT"\n    }\n  ], \n  "fingerprint": "y=", \n  "full_name": "fake_full_name222", \n  "kind": "compute#networkInterface", \n  "name": "nic0", \n  "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/default", \n  "networkIP": "1.2.0.2", \n  "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/default"\n}'),
     RuleViolation(resource_type='instance', resource_name='dev-project', full_name='fake_full_name222', rule_blacklist='ET', rule_name='ET', rule_index=0, violation_type='BLACKLIST_VIOLATION', project='dev-project', network='testnetwork', ip='5.6.7.8', resource_data='{\n  "accessConfigs": [\n    {\n      "kind": "compute#accessConfig", \n      "name": "External NAT", \n      "natIP": "5.6.7.8", \n      "type": "ONE_TO_ONE_NAT"\n    }\n  ], \n  "fingerprint": "z=", \n  "full_name": "fake_full_name222", \n  "kind": "compute#networkInterface", \n  "name": "nic1", \n  "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/testnetwork", \n  "networkIP": "1.1.0.2", \n  "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/sadadasd"\n}')],
    [RuleViolation(resource_type='instance', resource_name='dev-project', full_name='fake_full_name333', rule_blacklist='Spam', rule_name='Spam', rule_index=1, violation_type='BLACKLIST_VIOLATION', project='dev-project', network='testnetwork', ip='5.5.5.5', resource_data='{\n  "accessConfigs": [\n    {\n      "kind": "compute#accessConfig", \n      "name": "External NAT", \n      "natIP": "5.5.5.5", \n      "type": "ONE_TO_ONE_NAT"\n    }\n  ], \n  "fingerprint": "c=", \n  "full_name": "fake_full_name333", \n  "kind": "compute#networkInterface", \n  "name": "nic1", \n  "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/testnetwork", \n  "networkIP": "1.1.0.3", \n  "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/asia-east1/subnetworks/sadadasd"\n}')],
    [RuleViolation(resource_type='instance', resource_name='dev-project', full_name='fake_full_name444', rule_blacklist='ET', rule_name='ET', rule_index=0, violation_type='BLACKLIST_VIOLATION', project='dev-project', network='default', ip='5.6.7.254', resource_data='{\n  "accessConfigs": [\n    {\n      "kind": "compute#accessConfig", \n      "name": "External NAT", \n      "natIP": "5.6.7.254", \n      "type": "ONE_TO_ONE_NAT"\n    }\n  ], \n  "fingerprint": "v=", \n  "full_name": "fake_full_name444", \n  "kind": "compute#networkInterface", \n  "name": "nic0", \n  "network": "https://www.googleapis.com/compute/beta/projects/dev-project/global/networks/default", \n  "networkIP": "1.2.0.2", \n  "subnetwork": "https://www.googleapis.com/compute/beta/projects/dev-project/regions/us-east4/subnetworks/default"\n}')]
]
