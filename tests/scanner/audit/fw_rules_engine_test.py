"""Tests for google3.experimental.users.mwwolters.forseti.forseti-security.tests.scanner.audit.fw_rules_engine."""

import mock
import json
import unittest
import parameterized

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_type.firewall_rule import FirewallRule
from google.cloud.security.common.gcp_type.organization import Organization
from google.cloud.security.common.gcp_type.project import Project
from google.cloud.security.scanner.audit.errors import InvalidRulesSchemaError
from google.cloud.security.scanner.audit import fw_rules_engine as fre
from google.cloud.security.scanner.audit import rules as scanner_rules
from tests.unittest_utils import get_datafile_path
from tests.scanner.audit.data import test_rules


class FwRulesEngineTest(ForsetiTestCase):

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
            'rule_name': 'No 0.0.0.0/0 policy allowed',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_allowed': json.dumps(['*']),
            }],
            'verify_policies': [{
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            }],
            'mode': scanner_rules.RuleMode.BLACKLIST,
            'applies_to': 'self',
            'inherit_from_parents': False,
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
            'rule_name': 'No 0.0.0.0/0 policy allowed',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_allowed': json.dumps(['*']),
            }],
            'verify_policies': [{
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            }],
            'mode': scanner_rules.RuleMode.BLACKLIST,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [{
              'project_id': 'p1',
              'firewall_rule_name': '0.0.0.0/0',
              'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['22']}]),
          }],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'No 0.0.0.0/0 policy allowed',
                  'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                  'policy_names': ['0.0.0.0/0'],
              },
          ],
      ),
      (
          {
            'rule_name': 'No 0.0.0.0/0 policy allowed 2',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_allowed': json.dumps(['*']),
            }],
            'verify_policies': [{
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            }],
            'mode': scanner_rules.RuleMode.BLACKLIST,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'project_id': 'p1',
                  'firewall_rule_name': '0.0.0.0/0',
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'project_id': 'p2',
                  'firewall_rule_name': '0.0.0.0/0 2',
                  'firewall_rule_source_ranges': json.dumps(
                      ['1.1.1.1', '0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'all'}]),
              }
          ],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'No 0.0.0.0/0 policy allowed 2',
                  'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                  'policy_names': ['0.0.0.0/0'],
              },
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p2',
                  'rule_name': 'No 0.0.0.0/0 policy allowed 2',
                  'violation_type': 'FIREWALL_BLACKLIST_VIOLATION',
                  'policy_names': ['0.0.0.0/0 2'],
              },
          ],
      ),
    ])
    def test_find_policy_violations_blacklist(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            policy = FirewallRule(**policy_dict)
            policies.append(policy)
        violations = list(rule.find_policy_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    @parameterized.parameterized.expand([
      (
          {
            'rule_name': 'Only Allow 443 to tagged instances',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_action': 'allow',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['443']}]),
            }],
            'verify_policies': [{
              'firewall_rule_source_tags': json.dumps(['https-server']),
              'firewall_rule_allowed': json.dumps(['*']),
            }],
            'mode': scanner_rules.RuleMode.WHITELIST,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [{
              'firewall_rule_name': 'Any to 443 on https-server',
              'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_source_tags': json.dumps(['https-server']),
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['443']}]),
          }],
          [],
      ),
      (
          {
            'rule_name': 'Only Allow 443 to tagged instances',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_action': 'allow',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['443']}]),
            }],
            'verify_policies': [{
              'firewall_rule_source_tags': json.dumps(['https-server']),
              'firewall_rule_allowed': json.dumps(['*']),
            }],
            'mode': scanner_rules.RuleMode.WHITELIST,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [{
              'project_id': 'p1',
              'firewall_rule_name': 'Any to 443 on https-server',
              'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
              'firewall_rule_direction': 'ingress',
              'firewall_rule_source_tags': json.dumps(['https-server', 'tag2']),
              'firewall_rule_allowed': json.dumps(
                  [{'IPProtocol': 'tcp', 'ports': ['443']}]),
          }],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'Only Allow 443 to tagged instances',
                  'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                  'policy_names': ['Any to 443 on https-server'],
              },
          ],
      ),
      (
          {
            'rule_name': 'Only Allow 443 to tagged instances',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_action': 'allow',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['443']}]),
            }],
            'verify_policies': [{
              'firewall_rule_source_tags': json.dumps(['https-server']),
              'firewall_rule_allowed': json.dumps(['*']),
            }],
            'mode': scanner_rules.RuleMode.WHITELIST,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'project_id': 'p1',
                  'firewall_rule_name': 'Any to 443 on https-server',
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_source_tags': json.dumps(['tag1', 'tag2']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
              {
                  'project_id': 'p2',
                  'firewall_rule_name': 'Any to 443 on https-server',
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_source_tags': json.dumps(['https-server']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
              {
                  'project_id': 'p3',
                  'firewall_rule_name': (
                      'Any to 80/443 to https-server and tag3'),
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_source_tags': json.dumps(
                      ['https-server', 'tag3']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443', '80']}]),
              },
          ],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'Only Allow 443 to tagged instances',
                  'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                  'policy_names': ['Any to 443 on https-server'],
              },
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p3',
                  'rule_name': 'Only Allow 443 to tagged instances',
                  'violation_type': 'FIREWALL_WHITELIST_VIOLATION',
                  'policy_names': ['Any to 80/443 to https-server and tag3'],
              },
          ],
      ),
    ])
    def test_find_policy_violations_whitelist(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            policy = FirewallRule(**policy_dict)
            policies.append(policy)
        violations = list(rule.find_policy_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    @parameterized.parameterized.expand([
      (
          {
            'rule_name': 'Allow SSH to tag from 1.1.1.1',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_action': 'allow',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            }],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.REQUIRED,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'firewall_rule_name': 'Any to 443',
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
              {
                  'firewall_rule_name': 'Allow 22 from 1.1.1.1',
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
          ],
          [],
      ),
      (
          {
            'rule_name': 'Allow SSH to tag from 1.1.1.1',
            'match_policies': [{
                'firewall_rule_direction': 'ingress',
                'firewall_rule_action': 'allow',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            }],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.REQUIRED,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'project_id': 'p1',
                  'firewall_rule_name': 'Any to 443',
                  'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
              {
                  'project_id': 'p1',
                  'firewall_rule_name': 'Allow 22 from 1.1.1.1',
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.2']),
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
          ],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'Allow SSH to tag from 1.1.1.1',
                  'violation_type': 'FIREWALL_REQUIRED_VIOLATION',
                  'policy_names': ['Any to 443', 'Allow 22 from 1.1.1.1'],
              },
          ],
      ),
    ])
    def test_find_policy_violations_exists(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            policy = FirewallRule(**policy_dict)
            policies.append(policy)
        violations = list(rule.find_policy_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    @parameterized.parameterized.expand([
      (
          {
            'rule_name': 'Golden Policy',
            'match_policies': [
                {
                    'firewall_rule_direction': 'ingress',
                    'firewall_rule_action': 'allow',
                    'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                    'firewall_rule_allowed': json.dumps(
                        [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                },
                {
                    'firewall_rule_direction': 'ingress',
                    'firewall_rule_action': 'allow',
                    'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                    'firewall_rule_allowed': json.dumps(
                        [{'IPProtocol': 'tcp', 'ports': ['443']}]),
                },
            ],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.MATCHES,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'firewall_rule_name': 'SSH from 1.1.1.1',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'firewall_rule_name': '443 from 10.0.0.0/8',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
          ],
          [],
      ),
      (
          {
            'rule_name': 'Golden Policy',
            'match_policies': [
                {
                    'firewall_rule_direction': 'ingress',
                    'firewall_rule_action': 'allow',
                    'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                    'firewall_rule_allowed': json.dumps(
                        [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                },
                {
                    'firewall_rule_direction': 'ingress',
                    'firewall_rule_action': 'allow',
                    'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                    'firewall_rule_allowed': json.dumps(
                        [{'IPProtocol': 'tcp', 'ports': ['443']}]),
                },
            ],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.MATCHES,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'project_id': 'p1',
                  'firewall_rule_name': 'SSH from 1.1.1.1',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'project_id': 'p1',
                  'firewall_rule_name': '443 from 10.0.0.0/8',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['443']}]),
              },
              {
                  'project_id': 'p1',
                  'firewall_rule_name': '80 from 10.0.0.0/8',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['80']}]),
              },
          ],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'Golden Policy',
                  'violation_type': 'FIREWALL_MATCHES_VIOLATION',
                  'policy_names': [
                      'SSH from 1.1.1.1', '443 from 10.0.0.0/8',
                      '80 from 10.0.0.0/8'
                  ],
              },
          ],
      ),
      (
          {
            'rule_name': 'Golden Policy',
            'match_policies': [
                {
                    'firewall_rule_direction': 'ingress',
                    'firewall_rule_action': 'allow',
                    'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                    'firewall_rule_allowed': json.dumps(
                        [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                },
                {
                    'firewall_rule_direction': 'ingress',
                    'firewall_rule_action': 'allow',
                    'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                    'firewall_rule_allowed': json.dumps(
                        [{'IPProtocol': 'tcp', 'ports': ['443']}]),
                },
            ],
            'verify_policies': [],
            'mode': scanner_rules.RuleMode.MATCHES,
            'applies_to': 'self',
            'inherit_from_parents': False,
          },
          [
              {
                  'project_id': 'p1',
                  'firewall_rule_name': 'SSH from 1.1.1.1',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['22']}]),
              },
              {
                  'project_id': 'p1',
                  'firewall_rule_name': '80 from 10.0.0.0/8',
                  'firewall_rule_direction': 'ingress',
                  'firewall_rule_action': 'allow',
                  'firewall_rule_source_ranges': json.dumps(['10.0.0.0/8']),
                  'firewall_rule_allowed': json.dumps(
                      [{'IPProtocol': 'tcp', 'ports': ['80']}]),
              },
          ],
          [
              {
                  'resource_type': 'firewall_policy',
                  'resource_id': 'p1',
                  'rule_name': 'Golden Policy',
                  'violation_type': 'FIREWALL_MATCHES_VIOLATION',
                  'policy_names': ['SSH from 1.1.1.1', '80 from 10.0.0.0/8'],
              },
          ],
      ),
    ])
    def test_find_policy_violations_matches(
        self, rule_dict, policy_dicts, expected):
        rule = fre.Rule(**rule_dict)
        policies = []
        for policy_dict in policy_dicts:
            policy = FirewallRule(**policy_dict)
            policies.append(policy)
        violations = list(rule.find_policy_violations(policies))
        self.assert_rule_violation_lists_equal(expected, violations)

    def assert_rule_violation_lists_equal(self, expected, violations):
        sorted(expected, key=lambda k: k['resource_id'])
        sorted(violations, key=lambda k: k.resource_id)
        self.assertTrue(len(expected) == len(violations))
        for expected_dict, violation in zip(expected, violations):
            self.assertItemsEqual(expected_dict.values(), list(violation))


if __name__ == '__main__':
  unittest.main()
