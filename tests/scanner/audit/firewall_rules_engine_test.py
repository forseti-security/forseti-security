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

import mock
import json
import unittest
import parameterized

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import resource as resource_mod
from google.cloud.forseti.common.gcp_type.firewall_rule import FirewallRule
from google.cloud.forseti.scanner.audit import firewall_rules_engine as fre
from google.cloud.forseti.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path


class RuleTest(ForsetiTestCase):
    
    @parameterized.parameterized.expand([
        (
            {},
            fre.InvalidRuleDefinition,
            'Rule requires rule_id',
        ),
        (
            {'rule_id': 'id'},
            fre.InvalidRuleDefinition,
            'Rule requires mode',
        ),
        (
            {
                'rule_id': 'id',
                'mode': 'notavalidmode',
            },
            fre.InvalidRuleDefinition,
            'Mode notavalidmode is not in valid modes',
        ),
    ])
    def test_from_config_errors(self, rule_def, expected_error, regexp):
        with self.assertRaisesRegexp(expected_error, regexp):
            fre.Rule.from_config(rule_def)

    @parameterized.parameterized.expand([
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'egress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n2',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'udp', 'ports': ['22']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          False,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['23']}]),
          },
          True,
      ),
    ])
    def test_is_whitelist_violation(self, rule_dicts, policy_dict, expected):
        rules = [FirewallRule(**rule_dict) for rule_dict in rule_dicts]
        policy = FirewallRule(**policy_dict)
        self.assertEqual(expected, fre.is_whitelist_violation(rules, policy))

    @parameterized.parameterized.expand([
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          False,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'egress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          False,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n2',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          False,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'udp', 'ports': ['22']}]),
          },
          False,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['23']}]),
          },
          False,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['2', '1', '3']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['1-3']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['2', '1', '3']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['1-100']}]),
          },
          True,
      ),
      (
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['2', '1', '3']}]),
              }
          ],
          {
              'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['1-100']}]),
          },
          True,
      ),
    ])
    def test_is_blacklist_violation(self, rule_dicts, policy_dict, expected):
        rules = [FirewallRule(**rule_dict) for rule_dict in rule_dicts]
        policy = FirewallRule(**policy_dict)
        self.assertEqual(expected, fre.is_blacklist_violation(rules, policy))

    @parameterized.parameterized.expand([
      (
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          [{
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          }],
          False,
      ),
      (
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'egress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
          ],
          False,
      ),
      (
          {
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          },
          [
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'egress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_network': 'n1',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['23']}]),
              },
          ],
          True,
      ),
    ])
    def test_is_rule_exists_violation(self, rule_dict, policy_dicts, expected):
        rule = FirewallRule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            policy = FirewallRule(**policy_dict)
            policies.append(policy)
        self.assertEqual(expected, fre.is_rule_exists_violation(rule, policies))

    @parameterized.parameterized.expand([
      (
          {
            'rule_id': 'No 0.0.0.0/0 policy allowed',
            'match_policies': [{
                'direction': 'ingress',
                'allowed': ['*'],
            }],
            'verify_policies': [{
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': ['*'],
            }],
            'mode': scanner_rules.RuleMode.BLACKLIST,
          },
          [{
              'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_network': 'n1',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          }],
          [],
      ),
      (
          {
            'rule_id': 'No 0.0.0.0/0 policy allowed',
            'match_policies': [{
                'direction': 'ingress',
                'allowed': ['*'],
            }],
            'verify_policies': [{
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': ['*'],
            }],
            'mode': scanner_rules.RuleMode.BLACKLIST,
          },
          [{
              'project_id': 'p1',
              'firewall_rule_name': '0.0.0.0/0',
              'firewall_rule_network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
              'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          }],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': '0.0.0.0/0',
                  'full_name': '',
                  'rule_id': 'No 0.0.0.0/0 policy allowed',
                  'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                  'policy_names': ['0.0.0.0/0'],
                  'recommended_actions': {
                      'DELETE_FIREWALL_RULES': [
                          '0.0.0.0/0'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "0.0.0.0/0", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0"]}']
              },
          ],
      ),
      (
          {
            'rule_id': 'No 0.0.0.0/0 policy allowed 2',
            'match_policies': [{
                'direction': 'ingress',
                'allowed': ['*'],
            }],
            'verify_policies': [{
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': ['*'],
            }],
            'mode': scanner_rules.RuleMode.BLACKLIST,
          },
          [
              {
                  'project_id': 'p1',
                  'firewall_rule_name': '0.0.0.0/0',
                  'firewall_rule_network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'project_id': 'p2',
                  'firewall_rule_name': '0.0.0.0/0 2',
                  'firewall_rule_network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'firewall_rule_source_ranges': json.dumps(
                      ['1.1.1.1', '0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'all'}]),
              }
          ],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': '0.0.0.0/0',
                  'full_name': '',
                  'rule_id': 'No 0.0.0.0/0 policy allowed 2',
                  'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                  'policy_names': ['0.0.0.0/0'],
                  'recommended_actions': {
                      'DELETE_FIREWALL_RULES': [
                          '0.0.0.0/0'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "0.0.0.0/0", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0"]}']
              },
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p2',
                  'resource_name': '0.0.0.0/0 2',
                  'full_name': '',
                  'rule_id': 'No 0.0.0.0/0 policy allowed 2',
                  'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                  'policy_names': ['0.0.0.0/0 2'],
                  'recommended_actions': {
                      'DELETE_FIREWALL_RULES': [
                          '0.0.0.0/0 2'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "all"}], "direction": "INGRESS", "name": "0.0.0.0/0 2", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0", "1.1.1.1"]}']
              },
          ],
      ),
    ])
    def test_find_violations_blacklist(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            policy = FirewallRule(**policy_dict)
            policies.append(policy)
        violations = list(rule.find_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    @parameterized.parameterized.expand([
      (
          {
            'rule_id': 'Only Allow 443 to tagged instances',
            'match_policies': [{
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
            }],
            'verify_policies': [{
              'sourceTags': ['https-server'],
              'allowed': ['*'],
            }],
            'mode': scanner_rules.RuleMode.WHITELIST,
          },
          [{
              'name': 'Any to 443 on https-server',
              'sourceRanges': ['0.0.0.0/0'],
              'direction': 'ingress',
              'sourceTags': ['https-server'],
              'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
          }],
          [],
      ),
      (
          {
            'rule_id': 'Only Allow 443 to tagged instances',
            'match_policies': [{
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
            }],
            'verify_policies': [{
              'sourceTags': ['https-server'],
              'allowed': ['*'],
            }],
            'mode': scanner_rules.RuleMode.WHITELIST,
          },
          [{
              'project_id': 'p1',
              'name': 'Any to 443 on https-server',
              'network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
              'sourceRanges': ['0.0.0.0/0'],
              'direction': 'ingress',
              'sourceTags': ['https-server', 'tag2'],
              'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
          }],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': 'Any to 443 on https-server',
                  'full_name': None,
                  'rule_id': 'Only Allow 443 to tagged instances',
                  'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                  'policy_names': ['Any to 443 on https-server'],
                  'recommended_actions': {
                      'DELETE_FIREWALL_RULES': [
                          'Any to 443 on https-server'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}], "direction": "INGRESS", "name": "Any to 443 on https-server", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0"], "sourceTags": ["https-server", "tag2"]}']
              },
          ],
      ),
      (
          {
            'rule_id': 'Only Allow 443 to tagged instances',
            'match_policies': [{
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
            }],
            'verify_policies': [{
              'sourceTags': ['https-server'],
              'allowed': ['*'],
            }],
            'mode': scanner_rules.RuleMode.WHITELIST,
          },
          [
              {
                  'project_id': 'p1',
                  'name': 'Any to 443 on https-server',
                  'network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'sourceRanges': ['0.0.0.0/0'],
                  'direction': 'ingress',
                  'sourceTags': ['tag1', 'tag2'],
                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
              },
              {
                  'project_id': 'p2',
                  'name': 'Any to 443 on https-server',
                  'network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'sourceRanges': ['0.0.0.0/0'],
                  'direction': 'ingress',
                  'sourceTags': ['https-server'],
                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
              },
              {
                  'project_id': 'p3',
                  'name': 'Any to 80/443 to https-server and tag3',
                  'network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'sourceRanges': ['0.0.0.0/0'],
                  'direction': 'ingress',
                  'sourceTags': ['https-server', 'tag3'],
                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['443', '80']}],
              },
          ],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': 'Any to 443 on https-server',
                  'full_name': None,
                  'rule_id': 'Only Allow 443 to tagged instances',
                  'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                  'policy_names': ['Any to 443 on https-server'],
                  'recommended_actions': {
                      'DELETE_FIREWALL_RULES': [
                          'Any to 443 on https-server'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}], "direction": "INGRESS", "name": "Any to 443 on https-server", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0"], "sourceTags": ["tag1", "tag2"]}']
              },
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p3',
                  'resource_name': 'Any to 80/443 to https-server and tag3',
                  'full_name': None,
                  'rule_id': 'Only Allow 443 to tagged instances',
                  'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                  'policy_names': ['Any to 80/443 to https-server and tag3'],
                  'recommended_actions': {
                      'DELETE_FIREWALL_RULES': [
                          'Any to 80/443 to https-server and tag3'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["80", "443"]}], "direction": "INGRESS", "name": "Any to 80/443 to https-server and tag3", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0"], "sourceTags": ["https-server", "tag3"]}']
              },
          ],
      ),
    ])
    def test_find_violations_whitelist(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            project = policy_dict.get('project_id')
            policy = FirewallRule.from_dict(policy_dict, project_id=project)
            policies.append(policy)
        violations = list(rule.find_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    @parameterized.parameterized.expand([
      (
          {
            'rule_id': 'Allow SSH to tag from 1.1.1.1',
            'match_policies': [{
                'name': 'name',
                'network': 'network',
                'direction': 'ingress',
                'action': 'allow',
                'sourceRanges': ['1.1.1.1'],
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
            }],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.REQUIRED,
          },
          [
              {
                  'name': 'Any to 443',
                  'sourceRanges': ['0.0.0.0/0'],
                  'direction': 'ingress',
                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
              },
              {
                  'name': 'Allow 22 from 1.1.1.1',
                  'network': 'network',
                  'sourceRanges': ['1.1.1.1'],
                  'direction': 'ingress',
                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
              },
          ],
          [],
      ),
      (
          {
            'rule_id': 'Allow SSH to tag from 1.1.1.1',
            'match_policies': [{
                'name': 'name',
                'network': 'network',
                'direction': 'ingress',
                'action': 'allow',
                'sourceRanges': ['1.1.1.1'],
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
            }],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.REQUIRED,
          },
          [
              {
                  'project_id': 'p1',
                  'name': 'Any to 443',
                  'network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'sourceRanges': ['0.0.0.0/0'],
                  'direction': 'ingress',
                  'allowed': [{'IPProtocol': 'tcp', 'ports': ['443']}],
              },
              {
                  'project_id': 'p1',
                  'name': 'Allow 22 from 1.1.1.1',
                  'network': 'https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default',
                  'sourceRanges': ['1.1.1.2'],
                  'direction': 'ingress',
                  'allowed': [
                      {'IPProtocol': 'tcp', 'ports': ['22']}],
              },
          ],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': 'Any to 443,Allow 22 from 1.1.1.1',
                  'full_name': None,
                  'rule_id': 'Allow SSH to tag from 1.1.1.1',
                  'violation_type': 'FIREWALL_REQUIRED_VIOLATION',
                  'policy_names': ['Any to 443', 'Allow 22 from 1.1.1.1'],
                  'recommended_actions': {
                      'INSERT_FIREWALL_RULES': [
                          'Allow SSH to tag from 1.1.1.1: rule 0'
                      ]
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}], "direction": "INGRESS", "name": "Any to 443", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["0.0.0.0/0"]}', '{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "Allow 22 from 1.1.1.1", "network": "https://www.googleapis.com/compute/v1/projects/yourproject/global/networks/default", "sourceRanges": ["1.1.1.2"]}']
              },
          ],
      ),
    ])
    def test_find_violations_exists(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            project = policy_dict.get('project_id')
            policy = FirewallRule.from_dict(policy_dict, project_id=project)
            policies.append(policy)
        violations = list(rule.find_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    @parameterized.parameterized.expand([
      (
          {
            'rule_id': 'Golden Policy',
            'match_policies': [
                {
                    'name': 'name',
                    'network': 'network',
                    'direction': 'ingress',
                    'action': 'allow',
                    'sourceRanges': (['1.1.1.1']),
                    'allowed': (
                        [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                },
                {
                    'name': 'name',
                    'network': 'network',
                    'direction': 'ingress',
                    'action': 'allow',
                    'sourceRanges': (['10.0.0.0/8']),
                    'allowed': (
                        [{'IPProtocol': 'tcp', 'ports': ['443']}]),
                },
            ],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.MATCHES,
          },
          [
              {
                  'name': 'SSH from 1.1.1.1',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['1.1.1.1']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'name': '443 from 10.0.0.0/8',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['10.0.0.0/8']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
          ],
          [],
      ),
      (
          {
            'rule_id': 'Golden Policy',
            'match_policies': [
                {
                    'name': 'name',
                    'network': 'network',
                    'direction': 'ingress',
                    'action': 'allow',
                    'sourceRanges': (['1.1.1.1']),
                    'allowed': (
                        [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                },
                {
                    'name': 'name',
                    'network': 'network',
                    'direction': 'ingress',
                    'action': 'allow',
                    'sourceRanges': (['10.0.0.0/8']),
                    'allowed': (
                        [{'IPProtocol': 'tcp', 'ports': ['443']}]),
                },
            ],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.MATCHES,
          },
          [
              {
                  'project_id': 'p1',
                  'name': 'SSH from 1.1.1.1',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['1.1.1.1']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'project_id': 'p1',
                  'name': '443 from 10.0.0.0/8',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['10.0.0.0/8']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
              {
                  'project_id': 'p1',
                  'name': '80 from 10.0.0.0/8',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['10.0.0.0/8']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['80']}]),
              },
          ],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': 'SSH from 1.1.1.1,443 from 10.0.0.0/8,80 from 10.0.0.0/8',
                  'rule_id': 'Golden Policy',
                  'full_name': None,
                  'violation_type': 'FIREWALL_MATCHES_VIOLATION',
                  'policy_names': [
                      'SSH from 1.1.1.1', '443 from 10.0.0.0/8',
                      '80 from 10.0.0.0/8'
                  ],
                  'recommended_actions': {
                      'INSERT_FIREWALL_RULES': [],
                      'DELETE_FIREWALL_RULES': [
                          '80 from 10.0.0.0/8'
                      ],
                      'UPDATE_FIREWALL_RULES': [],
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "SSH from 1.1.1.1", "network": "network", "sourceRanges": ["1.1.1.1"]}', '{"allowed": [{"IPProtocol": "tcp", "ports": ["443"]}], "direction": "INGRESS", "name": "443 from 10.0.0.0/8", "network": "network", "sourceRanges": ["10.0.0.0/8"]}', '{"allowed": [{"IPProtocol": "tcp", "ports": ["80"]}], "direction": "INGRESS", "name": "80 from 10.0.0.0/8", "network": "network", "sourceRanges": ["10.0.0.0/8"]}']
              },
          ],
      ),
      (
          {
            'rule_id': 'Golden Policy',
            'match_policies': [
                {
                    'name': 'name',
                    'network': 'network',
                    'direction': 'ingress',
                    'action': 'allow',
                    'sourceRanges': (['1.1.1.1']),
                    'allowed': (
                        [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                },
                {
                    'name': 'name',
                    'network': 'network',
                    'direction': 'ingress',
                    'action': 'allow',
                    'sourceRanges': (['10.0.0.0/8']),
                    'allowed': (
                        [{'IPProtocol': 'tcp', 'ports': ['443']}]),
                },
            ],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.MATCHES,
          },
          [
              {
                  'project_id': 'p1',
                  'name': 'SSH from 1.1.1.1',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['1.1.1.1']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'project_id': 'p1',
                  'name': '80 from 10.0.0.0/8',
                  'network': 'network',
                  'direction': 'ingress',
                  'action': 'allow',
                  'sourceRanges': (['10.0.0.0/8']),
                  'allowed': (
                      [{'IPProtocol': 'tcp', 'ports': ['80']}]),
              },
          ],
          [
              {
                  'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                  'resource_id': 'p1',
                  'resource_name': 'SSH from 1.1.1.1,80 from 10.0.0.0/8',
                  'rule_id': 'Golden Policy',
                  'full_name': None,
                  'violation_type': 'FIREWALL_MATCHES_VIOLATION',
                  'policy_names': ['SSH from 1.1.1.1', '80 from 10.0.0.0/8'],
                  'recommended_actions': {
                      'INSERT_FIREWALL_RULES': [
                          'Golden Policy: rule 1'
                      ],
                      'DELETE_FIREWALL_RULES': [
                          '80 from 10.0.0.0/8'
                      ],
                      'UPDATE_FIREWALL_RULES': [],
                  },
                  'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "SSH from 1.1.1.1", "network": "network", "sourceRanges": ["1.1.1.1"]}', '{"allowed": [{"IPProtocol": "tcp", "ports": ["80"]}], "direction": "INGRESS", "name": "80 from 10.0.0.0/8", "network": "network", "sourceRanges": ["10.0.0.0/8"]}']
              },
          ],
      ),
    ])
    def test_find_violations_matches(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            project = policy_dict.get('project_id')
            policy = FirewallRule.from_dict(policy_dict, project_id=project)
            policies.append(policy)
        violations = list(rule.find_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k['resource_id'])
        sorted(violations, key=lambda k: k.resource_id)
        self.assertTrue(len(expected) == len(violations))
        for expected_dict, violation in zip(expected, violations):
            self.assertItemsEqual(expected_dict.values(), list(violation))


class RuleBookTest(ForsetiTestCase):

    @parameterized.parameterized.expand([
        (
            [
                {
                    'rule_id': 'id',
                    'mode': 'matches',
                    'match_policies': ['test'],
                },
                {
                    'rule_id': 'id',
                    'mode': 'matches',
                    'match_policies': ['test'],
                },
            ],
            fre.DuplicateFirewallRuleError,
            'Rule id "id" already in rules',
        ),
    ])
    def test_add_rule_errors(self, rule_defs, expected_error, regexp):
        rule_book = fre.RuleBook({})
        with self.assertRaisesRegexp(expected_error, regexp):
            for rule_def in rule_defs:
                rule_book.add_rule(rule_def, 1)

    @parameterized.parameterized.expand([
        (
            {'rule_id': 'id', 'mode': 'required', 'match_policies': ['test']},
        ),
    ])
    def test_add_rule(self, rule_def):
        rule_book = fre.RuleBook({})
        rule_book.add_rule(rule_def, 1)
        rule_id = rule_def.get('rule_id')
        self.assertTrue(rule_book.rules_map.get(rule_id) is not None)

    @parameterized.parameterized.expand([
        (
            [{}],
            fre.InvalidRuleDefinition,
            'Rule requires rule_id',
        ),
        (
            [{'rule_id': 'id'}],
            fre.InvalidRuleDefinition,
            'Rule requires mode',
        ),
        (
            [{
                'rule_id': 'id',
                'mode': 'notavalidmode',
            }],
            fre.InvalidRuleDefinition,
            'Mode notavalidmode is not in valid modes',
        ),
        (
            [
                {
                    'rule_id': 'id',
                    'mode': 'matches',
                    'match_policies': ['test'],
                },
                {
                    'rule_id': 'id',
                    'mode': 'matches',
                    'match_policies': ['test'],
                },
            ],
            fre.DuplicateFirewallRuleError,
            'Rule id "id" already in rules',
        ),
    ])
    def test_add_rules_errors(self, rule_defs, expected_error, regexp):
        rule_book = fre.RuleBook({})
        with self.assertRaisesRegexp(expected_error, regexp):
            rule_book.add_rules(rule_defs)

    @parameterized.parameterized.expand([
        (
            [
                {
                    'rule_id': 'id',
                    'mode': 'required',
                    'match_policies': ['test']
                },
                {
                    'rule_id': 'id2',
                    'mode': 'required',
                    'match_policies': ['test']
                },
            ],
        ),
    ])
    def test_add_rules(self, rule_defs):
        rule_book = fre.RuleBook({})
        rule_book.add_rules(rule_defs)
        for rule_def in rule_defs:
            rule_id = rule_def.get('rule_id')
            self.assertTrue(rule_book.rules_map.get(rule_id) is not None)

    @parameterized.parameterized.expand([
        (
            [{}],
            fre.InvalidGroupDefinition,
            'Group requires a group id',
        ),
        (
            [{'group_id': 'id'}],
            fre.InvalidGroupDefinition,
            'Group "id" does not have any rules',
        ),
        (
            [{'group_id': 'id', 'rule_ids': ['rid']}],
            fre.RuleDoesntExistError,
            'Rule id "rid" does not exist, cannot be in group',
        ),
    ])
    def test_add_rule_groups_errors(self, group_defs, expected_error, regexp):
        rule_book = fre.RuleBook({})
        with self.assertRaisesRegexp(expected_error, regexp):
            rule_book.add_rule_groups(group_defs)

    @parameterized.parameterized.expand([
        (
            [
                {
                    'group_id': 'id',
                    'rule_ids': ['rid1', 'rid2', 'rid3']
                },
                {
                    'group_id': 'id2',
                    'rule_ids': ['rid4']
                },
            ],
        ),
    ])
    def test_add_rule_groups(self, group_defs):
        rule_book = fre.RuleBook({})
        rule_book.rules_map['rid1'] = 'rule1'
        rule_book.rules_map['rid2'] = 'rule2'
        rule_book.rules_map['rid3'] = 'rule3'
        rule_book.rules_map['rid4'] = 'rule4'
        rule_book.add_rule_groups(group_defs)
        for group in group_defs:
            group_id = group.get('group_id')
            self.assertTrue(group_id in rule_book.rule_groups_map)
            self.assertItemsEqual(
                group.get('rule_ids'), rule_book.rule_groups_map[group_id])

    @parameterized.parameterized.expand([
        (
            {},
            fre.InvalidOrgDefinition,
            'Org policy does not have any resources',
        ),
        (
            {'resources': []},
            fre.InvalidOrgDefinition,
            'Org policy does not have any resources',
        ),
        (
            {'resources': [{}]},
            fre.resource_mod.errors.InvalidResourceTypeError,
            'Invalid resource type:',
        ),
        (
            {
                'resources': [
                    {
                        'type': 'organization',
                        'rules': {
                            'group_ids': ['id'],
                        },
                    }
                ]
            },
            fre.GroupDoesntExistError,
            'Group "id" does not exist',
        ),
        (
            {
                'resources': [
                    {
                        'type': 'organization',
                        'rules': {
                            'rule_ids': ['id'],
                        },
                    }
                ]
            },
            fre.RuleDoesntExistError,
            'Rule id "id" does not exist',
        ),
    ])
    def test_add_org_policy_errors(self, org_def, expected_error, regexp):
        rule_book = fre.RuleBook({})
        with self.assertRaisesRegexp(expected_error, regexp):
            rule_book.add_org_policy(org_def)

    def test_add_org_policy(self):
        rule_book = fre.RuleBook({})
        rule_book.rules_map['rule1'] = 1
        rule_book.rules_map['rule2'] = 2
        rule_book.rules_map['rule3'] = 3
        rule_book.rules_map['rule4'] = 4
        rule_book.rule_groups_map['gid1'] = ['rule3', 'rule4']
        org_def = {
          'resources': [
              {
                'type': 'folder',
                'resource_ids': ['res1', 'res2'],
                'rules': {
                    'rule_ids': ['rule1', 'rule2'],
                    'group_ids': ['gid1'],
                },
              },
          ],
        }
        rule_book.add_org_policy(org_def)
        gcp_resource_1 = fre.resource_util.create_resource(
            resource_id='res1', resource_type='folder')
        gcp_resource_2 = fre.resource_util.create_resource(
            resource_id='res2', resource_type='folder')
        self.assertItemsEqual(
            rule_book.org_policy_rules_map[gcp_resource_1],
            ['rule1', 'rule2', 'rule3', 'rule4'])
        self.assertItemsEqual(
            rule_book.org_policy_rules_map[gcp_resource_2],
            ['rule1', 'rule2', 'rule3', 'rule4'])

    def test_find_violations(self):
        rule_defs = [
            {
                'rule_id': 'rule1',
                'mode': 'blacklist',
                'match_policies': [
                    {
                        'direction': 'ingress',
                        'allowed': ['*'],
                        'targetTags': ['linux'],
                    },
                ],
                'verify_policies': [
                    {
                        'allowed': [{
                            'IPProtocol': 'tcp',
                            'ports': ['3389']
                        }],
                    }
                ],
            },
            {
                'rule_id': 'rule2',
                'mode': 'whitelist',
                'match_policies': [
                    {
                        'direction': 'ingress',
                        'allowed': ['*'],
                        'targetTags': ['test'],
                    },
                ],
                'verify_policies': [
                    {
                        'allowed': ['*'],
                        'sourceRanges': ['10.0.0.0/8'],
                    }
                ],
            },
            {
                'rule_id': 'rule3',
                'mode': 'required',
                'match_policies': [
                    {
                        'name': 'policy1',
                        'network': 'network1',
                        'direction': 'egress',
                        'denied': [{'IPProtocol': '*'}],
                        'destinationRanges': ['8.8.8.8'],
                    }
                ],
            },
            {
                'rule_id': 'rule4',
                'mode': 'matches',
                'match_policies': [
                    {
                      'name': 'policy1',
                      'network': 'network1',
                      'direction': 'ingress',
                      'allowed': [
                          {
                              'IPProtocol': 'tcp',
                              'ports': ['22'],
                          },
                      ],
                      'sourceRanges': ['0.0.0.0/0'],
                    }
                ],
            },
        ]
        group_defs = [
            {
                'group_id': 'gid1',
                'rule_ids': ['rule1', 'rule2'],
            },
        ]
        org_def = {
            'resources': [
                {
                    'type': 'organization',
                    'resource_ids': ['org'],
                    'rules': {
                        'rule_ids': ['rule4'],
                    },
                },
                {
                    'type': 'folder',
                    'resource_ids': ['folder1', 'folder2'],
                    'rules': {
                        'group_ids': ['gid1'],
                    },
                },
                {
                    'type': 'project',
                    'resource_ids': ['project2'],
                    'rules': {
                        'rule_ids': ['rule3'],
                    },
                },
                {
                    'type': 'project',
                    'resource_ids': ['exception'],
                    'rules': {
                        'rule_ids': [],
                    },
                },
            ],
        }
        project0 = fre.resource_util.create_resource(
            resource_id='project0', resource_type='project')
        project1 = fre.resource_util.create_resource(
            resource_id='project1', resource_type='project')
        project2 = fre.resource_util.create_resource(
            resource_id='project2', resource_type='project')
        project3 = fre.resource_util.create_resource(
            resource_id='project3', resource_type='project')
        exception = fre.resource_util.create_resource(
            resource_id='exception', resource_type='project')
        folder1 = fre.resource_util.create_resource(
            resource_id='folder1', resource_type='folder')
        folder2 = fre.resource_util.create_resource(
            resource_id='folder2', resource_type='folder')
        folder3 = fre.resource_util.create_resource(
            resource_id='folder3', resource_type='folder')
        folder4 = fre.resource_util.create_resource(
            resource_id='folder4', resource_type='folder')
        org = fre.resource_util.create_resource(
            resource_id='org', resource_type='organization')

        policy_violates_rule_1 = fre.firewall_rule.FirewallRule.from_dict(
            {
                'name': 'policy1',
                'full_name': 'organization/org/folder/folder1/project/project0/firewall/policy1/',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                'sourceRanges': ['0.0.0.0/0'],
                'targetTags': ['linux'],
            },
            validate=True,
        )
        policy_violates_rule_2 = fre.firewall_rule.FirewallRule.from_dict(
            {
                'name': 'policy1',
                'full_name': 'organization/org/folder/folder2/project/project1/firewall/policy1/',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['11.0.0.1'],
                'targetTags': ['test'],
            },
            validate=True,
        )
        policy_violates_rule_3 = fre.firewall_rule.FirewallRule.from_dict(
            {
                'name': 'policy1',
                'full_name': 'organization/org/folder/folder3/folder/folder4/project/project2/firewall/policy1/',
                'network': 'network1',
                'direction': 'egress',
                'denied': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'destinationRanges': ['11.0.0.1'],
            },
            validate=True,
        )
        policy_violates_rule_4 = fre.firewall_rule.FirewallRule.from_dict(
            {
                'name': 'policy1',
                'full_name': 'organization/org/folder/folder3/project/project3/firewall/policy1/',
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['0.0.0.0/1'],
            },
            validate=True,
        )
        ancestry = {
            project0: [folder1, org],
            project1: [folder2, org],
            project2: [folder4, folder3, org],
            project3: [folder3, org],
            exception: [folder3, org],
        }
        rule_book = fre.RuleBook(
            rule_defs=rule_defs,
            group_defs=group_defs,
            org_policy=org_def
        )
        rule_book.org_res_rel_dao = mock.Mock()
        rule_book.org_res_rel_dao.find_ancestors.side_effect = (
            lambda x,y: ancestry[x])
        project0_violations = [
            fre.RuleViolation(
                resource_type=resource_mod.ResourceType.FIREWALL_RULE,
                resource_id=None,
                resource_name='policy1',
                full_name='organization/org/folder/folder1/project/project0/firewall/policy1/',
                rule_id='rule1',
                violation_type='FIREWALL_BLACKLIST_VIOLATION',
                policy_names=['policy1'],
                recommended_actions={'DELETE_FIREWALL_RULES': ['policy1']},
                resource_data=['{"allowed": [{"IPProtocol": "tcp", "ports": ["1", "3389"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["0.0.0.0/0"], "targetTags": ["linux"]}']
            )
        ]
        project1_violations = [
            fre.RuleViolation(
                resource_type=resource_mod.ResourceType.FIREWALL_RULE,
                resource_id=None,
                resource_name='policy1',
                full_name='organization/org/folder/folder2/project/project1/firewall/policy1/',
                rule_id='rule2',
                violation_type='FIREWALL_WHITELIST_VIOLATION',
                policy_names=['policy1'],
                recommended_actions={'DELETE_FIREWALL_RULES': ['policy1']},
                resource_data=['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["11.0.0.1"], "targetTags": ["test"]}']
            )
        ]
        project2_violations = [
            fre.RuleViolation(
                resource_type=resource_mod.ResourceType.FIREWALL_RULE,
                resource_id=None,
                resource_name='policy1',
                full_name='organization/org/folder/folder3/folder/folder4/project/project2/firewall/policy1/',
                rule_id='rule3',
                violation_type='FIREWALL_REQUIRED_VIOLATION',
                policy_names=['policy1'],
                recommended_actions={'INSERT_FIREWALL_RULES': ['rule3: rule 0']},
                resource_data=['{"denied": [{"IPProtocol": "tcp", "ports": ["22"]}], "destinationRanges": ["11.0.0.1"], "direction": "EGRESS", "name": "policy1", "network": "network1"}']
            )
        ]
        project3_violations = [
            fre.RuleViolation(
                resource_type=resource_mod.ResourceType.FIREWALL_RULE,
                resource_id=None,
                resource_name='policy1',
                full_name='organization/org/folder/folder3/project/project3/firewall/policy1/',
                rule_id='rule4',
                violation_type='FIREWALL_MATCHES_VIOLATION',
                policy_names=['policy1'],
                recommended_actions={
                    'DELETE_FIREWALL_RULES': ['policy1'],
                    'UPDATE_FIREWALL_RULES': [],
                    'INSERT_FIREWALL_RULES': ['rule4: rule 0']
                },
                resource_data=['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["0.0.0.0/1"]}']
           )
        ]
        resources_and_policies = (
            (project0, policy_violates_rule_1, project0_violations),
            (project1, policy_violates_rule_2, project1_violations),
            (project2, policy_violates_rule_3, project2_violations),
            (project3, policy_violates_rule_4, project3_violations),
            (exception, policy_violates_rule_1, []),
        )

        self.maxDiff=None

        for resource, policy, expected_violation in resources_and_policies:
            violations = rule_book.find_violations(resource, [policy])
            self.assert_rule_violation_lists_equal(
                expected_violation, list(violations))

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k.resource_id)
        sorted(violations, key=lambda k: k.resource_id)
        self.assertItemsEqual(expected, violations)

class RuleEngineTest(ForsetiTestCase):

    def setUp(self):
        project0 = fre.resource_util.create_resource(
            resource_id='test_project', resource_type='project')
        project1 = fre.resource_util.create_resource(
            resource_id='project1', resource_type='project')
        project2 = fre.resource_util.create_resource(
            resource_id='project2', resource_type='project')
        project3 = fre.resource_util.create_resource(
            resource_id='project3', resource_type='project')
        exception = fre.resource_util.create_resource(
            resource_id='honeypot_exception', resource_type='project')
        folder1 = fre.resource_util.create_resource(
            resource_id='folder1', resource_type='folder')
        folder2 = fre.resource_util.create_resource(
            resource_id='test_instances', resource_type='folder')
        folder3 = fre.resource_util.create_resource(
            resource_id='folder3', resource_type='folder')
        folder4 = fre.resource_util.create_resource(
            resource_id='folder4', resource_type='folder')
        org = fre.resource_util.create_resource(
            resource_id='org', resource_type='organization')
        self.project_resource_map = {
            'test_project': project0,
            'project1': project1,
            'project2': project2,
            'project3': project3,
            'honeypot_exception': exception,
        }
        self.ancestry = {
            project0: [folder1, org],
            project1: [folder2, org],
            project2: [folder4, folder3, org],
            project3: [folder3, org],
            exception: [folder3, org],
        }

    def test_build_rule_book_from_yaml(self):
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        rules_engine = fre.FirewallRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        self.assertEqual(4, len(rules_engine.rule_book.rules_map))
        self.assertEqual(1, len(rules_engine.rule_book.rule_groups_map))
        self.assertEqual(6, len(rules_engine.rule_book.org_policy_rules_map))

    @parameterized.parameterized.expand([
        (
            'test_project',
            {
                'name': 'policy1',
                'full_name': ('organization/org/folder/folder1/'
                              'project/project0/firewall/policy1/'),
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                'sourceRanges': ['0.0.0.0/0'],
                'targetTags': ['linux'],
            },
            [
                {
                    'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                    'resource_id': None,
                    'resource_name': 'policy1',
                    'full_name': ('organization/org/folder/folder1/'
                                  'project/project0/firewall/policy1/'),
                    'rule_id': 'no_rdp_to_linux',
                    'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1']
                    },
                    'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["1", "3389"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["0.0.0.0/0"], "targetTags": ["linux"]}']
                }
            ],
        ),
        (
            'project1',
            {
                'name': 'policy1',
                'full_name': ('organization/org/folder/test_instances/'
                              'project/project1/firewall/policy1/'),
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['22']}],
                'sourceRanges': ['11.0.0.1'],
                'targetTags': ['test'],
            },
            [
                {
                    'resource_type': resource_mod.ResourceType.FIREWALL_RULE,
                    'resource_id': None,
                    'resource_name': 'policy1',
                    'full_name': ('organization/org/folder/test_instances/'
                                  'project/project1/firewall/policy1/'),
                    'rule_id': 'test_instances_rule',
                    'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                    'policy_names': ['policy1'],
                    'recommended_actions': {
                        'DELETE_FIREWALL_RULES': ['policy1']
                    },
                    'resource_data': ['{"allowed": [{"IPProtocol": "tcp", "ports": ["22"]}], "direction": "INGRESS", "name": "policy1", "network": "network1", "sourceRanges": ["11.0.0.1"], "targetTags": ["test"]}']
                }
            ],
        ),
        (
            'honeypot_exception',
            {
                'name': 'policy1',
                'full_name': ('organization/org/folder/folder1/'
                              'project/project0/firewall/policy1/'),
                'network': 'network1',
                'direction': 'ingress',
                'allowed': [{'IPProtocol': 'tcp', 'ports': ['1', '3389']}],
                'sourceRanges': ['0.0.0.0/0'],
                'targetTags': ['linux'],
            },
            [],
        ),
    ])
    def test_find_violations_from_yaml_rule_book(
        self, project, policy_dict, expected_violations_dicts):
        rules_local_path = get_datafile_path(
            __file__, 'firewall_test_rules.yaml')
        rules_engine = fre.FirewallRulesEngine(rules_file_path=rules_local_path)
        rules_engine.build_rule_book({})
        resource = self.project_resource_map[project]
        policy = fre.firewall_rule.FirewallRule.from_dict(
            policy_dict, validate=True)
        rules_engine.rule_book.org_res_rel_dao = mock.Mock()
        rules_engine.rule_book.org_res_rel_dao.find_ancestors.side_effect = (
            lambda x,y: self.ancestry[x])
        violations = rules_engine.find_violations(resource, [policy])
        expected_violations = [
            fre.RuleViolation(**v) for v in expected_violations_dicts]
        self.assert_rule_violation_lists_equal(expected_violations, violations)

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k.resource_id)
        sorted(violations, key=lambda k: k.resource_id)
        self.assertItemsEqual(expected, violations)


if __name__ == '__main__':
    unittest.main()
