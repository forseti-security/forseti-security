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

"""Test data for firewall rules scanners."""

FAKE_FIREWALL_RULE_FOR_TEST_PROJECT = {
    'name': 'policy1',
    'full_name': ('organization/org/folder/folder1/'
                  'project/project0/firewall/policy1/'),
    'network': 'network1',
    'direction': 'ingress',
    'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
    'sourceRanges': ['0.0.0.0/0'],
                    'targetTags': ['linux'],
    }

FAKE_FIREWALL_RULE_FOR_PROJECT1 = {
    'name': 'policy1',
    'full_name':
        ('organization/org/folder/test_instances/'
         'project/project1/firewall/policy1/'),
    'network': 'network1',
    'direction': 'ingress',
    'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
    'sourceRanges': ['11.0.0.1'],
    'targetTags': ['test'],
    }