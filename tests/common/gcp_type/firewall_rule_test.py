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

"""Tests for firewall_rule."""
import json
import unittest
import mock
import parameterized

from tests.common.gcp_type.test_data import fake_firewall_rules
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.gcp_type import firewall_rule


class FirewallRuleTest(ForsetiTestCase):
    """Tests for firewall_rule."""

    def test_from_json(self):
      json_dict = {
          'kind': 'compute#firewall',
          'id': '8',
          'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
          'name': 'default',
          'description': '',
          'network': 'network name',
          'priority': 1000,
          'sourceRanges': ['0.0.0.0/0'],
          'allowed': [
              {
                  'IPProtocol': 'tcp',
                  'ports': ['22']
              }
          ],
          'direction': 'INGRESS',
          'selfLink': 'https:// insert link here',
      }
      json_string = json.dumps(json_dict)
      rule = firewall_rule.FirewallRule.from_json(json_string)
      self.assertTrue(rule.validate())

    @parameterized.parameterized.expand([
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'name': 'default',
                'description': '',
                'network': 'network name',
                'priority': 1000,
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ],
                'direction': 'EGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Egress rule missing required field "destinationRanges".*',
        ),
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'description': '',
                'network': 'network name',
                'priority': 1000,
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ],
                'direction': 'INGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "name"',
        ),
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'description': '',
                'network': 'network name',
                'priority': 1000,
                'sourceRanges': ['0.0.0.0/0'],
                'direction': 'INGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Must have allowed or denied rules',
        ),
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'name': 'default',
                'description': '',
                'network': 'network name',
                'priority': -1,
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ],
                'direction': 'INGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule "priority" out of range 0-65535',
        ),
    ])
    def test_from_json_error(self, json_dict, expected_error, regexp):
      json_string = json.dumps(json_dict)
      with self.assertRaisesRegexp(expected_error, regexp):
          rule = firewall_rule.FirewallRule.from_json(json_string)

    def test_from_dict(self):
      firewall_dict = {
          'name': 'default',
          'network': 'network name',
          'priority': 1000,
          'sourceRanges': ['0.0.0.0/0'],
          'allowed': ['*'],
          'direction': 'INGRESS',
      }
      firewall_dict_2 = {
          'name': 'default',
          'network': 'network name',
          'priority': 1000,
          'sourceRanges': ['0.0.0.0/0'],
          'allowed': [
              {
                  'IPProtocol': 'tcp',
                  'ports': ['22']
              }
          ],
          'direction': 'INGRESS',
      }
      rule = firewall_rule.FirewallRule.from_dict(firewall_dict)
      rule_2 = firewall_rule.FirewallRule.from_dict(firewall_dict)
      self.assertTrue(rule_2 < rule)

    @parameterized.parameterized.expand([
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'name': 'default',
                'description': '',
                'network': 'network name',
                'priority': 1000,
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ],
                'direction': 'EGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Egress rule missing required field "destinationRanges".*',
        ),
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'description': '',
                'network': 'network name',
                'priority': 1000,
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ],
                'direction': 'INGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "name"',
        ),
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'description': '',
                'network': 'network name',
                'priority': 1000,
                'sourceRanges': ['0.0.0.0/0'],
                'direction': 'INGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Must have allowed or denied rules',
        ),
        (
            {
                'kind': 'compute#firewall',
                'id': '8',
                'creationTimestamp': '2017-05-01T22:08:53.399-07:00',
                'name': 'default',
                'description': '',
                'network': 'network name',
                'priority': -1,
                'sourceRanges': ['0.0.0.0/0'],
                'allowed': [
                    {
                        'IPProtocol': 'tcp',
                        'ports': ['22']
                    }
                ],
                'direction': 'INGRESS',
                'selfLink': 'https:// insert link here'
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule "priority" out of range 0-65535',
        ),
    ])
    def test_from_dict_error(self, firewall_dict, expected_error, regexp):
      with self.assertRaisesRegexp(expected_error, regexp):
          rule = firewall_rule.FirewallRule.from_dict(
              firewall_dict, validate=True)

    @parameterized.parameterized.expand([
        ('192.0.0.1', '192.0.0.1/24', True),
        ('192.0.0.1', '192.0.0.0/16', True),
        ('192.0.0.1/24', '192.0.0.0/16', True),
        ('192.0.0.1/24', '192.0.0.1', False),
        ('192.0.1.1', '192.0.0.0/16', True),
        ('192.0.1.1', '192.0.0.1/24', False),
        ('192.0.0.1/32', '192.0.0.0/16', True),
        ('192.0.0.2/32', '0.0.0.0/0', True),
        ('5.5.5.5', '192.0.0.0/16', False)])
    def test_ip_in_range(self, ip_addr, ip_range, expected):
        """Tests whether ip_in_range correctly detects ips in a range."""
        self.assertEqual(expected, firewall_rule.ip_in_range(ip_addr, ip_range))

    @parameterized.parameterized.expand([
        (['192.0.0.1'], ['192.0.0.1/24'], True),
        (['192.0.0.1'], ['192.0.0.0/16'], True),
        (['192.0.0.1/24'], ['192.0.0.0/16'], True),
        (['192.0.0.1/24'], ['192.0.0.1'], False),
    ])
    def test_ips_subset_of_ips(self, ips, ips_range, expected):
        """Tests whether ips_subset_of_ips returns the correct data."""
        self.assertEqual(expected, firewall_rule.ips_in_list(ips, ips_range))

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_source_tags': None,
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_priority': 'NaN',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            'Rule "priority" could not be converted to an integer: .*NaN.*',
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_priority': '-1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            'Rule "priority" out of range 0-65535: "-1".',
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_priority': '1000000000',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            'Rule "priority" out of range 0-65535: "1000000000"',
        ),
    ])
    def test_validate_priority_error(self, rule_dict, expected_regex):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaisesRegexp(firewall_rule.InvalidFirewallRuleError,
                                     expected_regex):
            rule._validate_priority()

    @parameterized.parameterized.expand([
        (  # ingress rule has no source ranges, tags, or service accounts
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            ('Ingress rule missing required field oneof "sourceRanges" or'
             ' "sourceTags" or "sourceServiceAccounts"'),
        ),
        (  # ingress rule has destination range
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_destination_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            'Ingress rules cannot include "destinationRanges"',
        ),
        (  # egress rule has no destination ranges
            {
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            'Egress rule missing required field "destinationRanges"',
        ),
        (  # egress rule has source ranges
            {
                'firewall_rule_destination_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            ('Egress rules cannot include "sourceRanges", "sourceTags" or'
             ' "sourceServiceAccounts"'),
        ),
        (  # egress rule has source tags
            {
                'firewall_rule_destination_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_source_tags': json.dumps(['t1']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            ('Egress rules cannot include "sourceRanges", "sourceTags" or'
             ' "sourceServiceAccounts"'),
        ),
    ])
    def test_validate_direction_error(self, rule_dict, expected_regex):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaisesRegexp(firewall_rule.InvalidFirewallRuleError,
                               expected_regex):
            rule._validate_direction()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "name"',
        ),
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "network"',
        ),
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_denied': json.dumps(
                    [
                        {'IPProtocol': 'tcp', 'ports': ['21-23']},
                        {},
                    ]),
            },
            firewall_rule.InvalidFirewallActionError,
            'Action must have field IPProtocol',
        ),
    ])
    def test_validate_errors(self, rule_dict, expected_error, regexp):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaisesRegexp(expected_error, regexp):
            rule.validate()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "name"',
        ),
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "network"',
        ),
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_denied': json.dumps(
                    [
                        {'IPProtocol': 'tcp', 'ports': ['21-23']},
                        {},
                    ]),
            },
            firewall_rule.InvalidFirewallActionError,
            'Action must have field IPProtocol',
        ),
    ])
    def test_as_json_error(self, rule_dict, expected_error, regexp):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaisesRegexp(expected_error, regexp):
            rule.as_json()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            {
                'denied': [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
                'direction': 'INGRESS',
                'network': 'n2',
                'name': 'n1',
                'sourceRanges': ['1.1.1.1'],
            },
        ),
    ])
    def test_as_json(self, rule_dict, expected):
        rule = firewall_rule.FirewallRule(**rule_dict)
        self.assertEqual(json.dumps(expected, sort_keys=True), rule.as_json())

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_network': 'n1',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "name"',
        ),
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule missing required field "network"',
        ),
        (
            {
                'firewall_rule_name': 'n'*64,
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule name exceeds length limit of 63 chars',
        ),
        (
            {
                'firewall_rule_name': 'n'*63,
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(
                    ['1.1.1.%s' % i for i in range(257)]),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule entry "sourceRanges" must contain 256 or fewer values',
        ),
        (
            {
                'firewall_rule_name': 'n'*63,
                'firewall_rule_network': 'n2',
                'firewall_rule_destination_ranges': json.dumps(
                    ['1.1.1.%s' % i for i in range(257)]),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule entry "destinationRanges" must contain 256 or fewer values',
        ),
        (
            {
                'firewall_rule_name': 'n'*63,
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(
                    ['1.1.1.%s' % i for i in range(256)]),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_source_tags': json.dumps(
                    ['t%s' % i for i in range(257)]),
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule entry "sourceTags" must contain 256 or fewer values',
        ),
        (
            {
                'firewall_rule_name': 'n'*63,
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(
                    ['1.1.1.%s' % i for i in range(256)]),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_target_tags': json.dumps(
                    ['t%s' % i for i in range(257)]),
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule entry "targetTags" must contain 256 or fewer values',
        ),
        (
            {
                'firewall_rule_name': 'n'*63,
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(
                    ['1.1.1.%s' % i for i in range(256)]),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                'firewall_rule_source_service_accounts': json.dumps(
                    ['sa1', 'sa2']),
            },
            firewall_rule.InvalidFirewallRuleError,
            'Rule entry "sourceServiceAccount" may contain at most 1 value',
        ),
        (
            {
                'firewall_rule_name': 'n'*63,
                'firewall_rule_network': 'n2',
                'firewall_rule_source_ranges': json.dumps(
                    ['1.1.1.%s' % i for i in range(256)]),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_target_tags': json.dumps(
                    ['t%s' % i for i in range(256)]),
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
                'firewall_rule_source_service_accounts': json.dumps(['sa1']),
            },
            firewall_rule.InvalidFirewallRuleError,
            ('targetTags cannot be set when source/targetServiceAccounts '
             'are set'),
        ),
    ])
    def test_validate_keys_error(self, rule_dict, expected_error, regexp):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaisesRegexp(expected_error, regexp):
            rule.validate()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['50-55']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['40-60']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            False,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_action': 'deny',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            False,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.2']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            False,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            True,
        ),
    ])
    def test_firewall_rule_lt(self, rule_1_dict, rule_2_dict, expected):
        """Tests that rule 1 < rule 2 returns the correct value."""
        rule_1 = firewall_rule.FirewallRule(**rule_1_dict)
        rule_2 = firewall_rule.FirewallRule(**rule_2_dict)
        self.assertEqual(expected, rule_1 < rule_2)

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.2']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            True,
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.1',
                                                                '10.0.0.2']),
                'firewall_rule_allowed': json.dumps(['*']),
                'firewall_rule_direction': 'egress',
            },
            True,
        ),
    ])
    def test_firewall_rule_gt(self, rule_1_dict, rule_2_dict, expected):
        """Tests that rule 1 > rule 2 returns the correct value."""
        rule_1 = firewall_rule.FirewallRule(**rule_1_dict)
        rule_2 = firewall_rule.FirewallRule(**rule_2_dict)
        self.assertEqual(expected, rule_1 > rule_2)

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
    ])
    def test_firewall_rule_eq(self, rule_1_dict, rule_2_dict, expected):
        """Tests that rule 1 == rule 2 returns the correct value."""
        rule_1 = firewall_rule.FirewallRule(**rule_1_dict)
        rule_2 = firewall_rule.FirewallRule(**rule_2_dict)
        self.assertEqual(expected, rule_1 == rule_2)

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'egress',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n2',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t3', 't2']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't5']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_source_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_destination_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_destination_ranges': json.dumps(['10.0.0.0/24']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['10', '11', '12', '13']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['10-13']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'INGRESS',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
    ])
    def test_firewall_rule_is_equivalent(
            self, rule_1_dict, rule_2_dict, expected):
        """Tests that rule 1 == rule 2 returns the correct value."""
        rule_1 = firewall_rule.FirewallRule(**rule_1_dict)
        rule_2 = firewall_rule.FirewallRule(**rule_2_dict)
        self.assertEqual(expected, rule_1.is_equivalent(rule_2))

    def test_load_firewall_rule(self):
        """Tests that loading to FirewallRule and exporting it as JSON works.

        This test depends on the data in
        tests/inventory/pipelines/test_data/fake_firewall_rules.py
        being formatted like:
          {
            <project_id>: [<firewall_rules>]
          }
        If a loadable firewall exists that isn't in the map, this test will
        fail.
        """
        expected_map = fake_firewall_rules.EXPECTED_FIREWALL_RULES_MAP
        for loadable_firewall in fake_firewall_rules.EXPECTED_LOADABLE_FIREWALL_RULES:
            rule = firewall_rule.FirewallRule(**loadable_firewall)
            dict_rule = json.loads(rule.as_json())
            expected_list = expected_map.get(rule.project_id)
            expected = {}
            for fw_rule in expected_list:
                if fw_rule['name'] == rule.name:
                    expected = fw_rule.copy()
            for key in ['kind', 'id', 'creationTimestamp', 'description',
                        'selfLink']:
                expected.pop(key)
            unicode_expected = json.loads(json.dumps(expected))
            unicode_expected['allowed'] = sorted(unicode_expected['allowed'])
            dict_rule['allowed'] = sorted(dict_rule['allowed'])
            self.maxDiff = None
            self.assertDictEqual(unicode_expected, dict_rule)


class FirewallActionTest(ForsetiTestCase):
    """Tests for FirewallAction."""

    @parameterized.parameterized.expand([
        (
            {'firewall_rules': [{}],},
            'Action must have field IPProtocol',
        ),
        (
            {
                'firewall_rules':
                [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']},
                    {},
                ],
            },
            'Action must have field IPProtocol',
        ),
        (
            {
                'firewall_rules':
                [
                    {'IPProtocol': 'tcp', 'ports': ['21-23'], 'invalid': 'test'},
                ],
            },
            'Action can only have "IPProtocol" and "ports"',
        ),
        (
            {
                'firewall_rules':
                [
                    {'IPProtocol': 'ucp', 'ports': ['21-23']},
                ],
            },
            'Only "tcp" and "udp" can have ports specified',
        ),
        (
            {
                'firewall_rules':
                [
                    {'IPProtocol': 'udp', 'ports': ['100-50']},
                ],
            },
            'Start port range > end port range',
        ),
        (
            {
                'firewall_rules':
                [
                    {'IPProtocol': 'udp', 'ports': ['0-5000000']},
                ],
            },
            'Port must be <= 65535',
        ),
    ])
    def test_validate_errors(self, action_1_dict, error_regexp):
        action = firewall_rule.FirewallAction(**action_1_dict)
        with self.assertRaisesRegexp(
            firewall_rule.InvalidFirewallActionError, error_regexp):
          action.validate()

    @parameterized.parameterized.expand([
        (
            {'firewall_rules': [{}]},
            'Action must have field IPProtocol',
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']},
                    {},
                ],
            },
            'Action must have field IPProtocol',
        ),
    ])
    def test_json_dict_errors(self, action_dict, error_regexp):
        action = firewall_rule.FirewallAction(**action_dict)
        with self.assertRaisesRegexp(
            firewall_rule.InvalidFirewallActionError, error_regexp):
          action.json_dict()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']},
                ],
            },
            'allowed', 
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']},
                    {'IPProtocol': 'udp'},
                ],
            },
            'allowed', 
        ),
    ])
    def test_json_dict(self, action_dict, direction):
        action = firewall_rule.FirewallAction(**action_dict)
        key, value = action.json_dict()
        self.assertEqual(direction, key)
        self.assertEqual(action_dict['firewall_rules'], value)

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            False,
        ),
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            True,
        ),
        (
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22', '23']},
                    ],
            },
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22', '21', '23']},
                    ],
            },
            True,
        ),
        (
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22', '23', '24']},
                    ],
            },
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22', '21', '23']},
                    ],
            },
            False,
        ),
        (
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22-23']},
                        {'IPProtocol': 'udp', 'ports': ['50', '55']},
                    ],
            },
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'udp', 'ports': ['49-55']},
                        {'IPProtocol': 'tcp', 'ports': ['22', '21', '23']},
                    ],
            },
            True,
        ),
        (
            {
                'firewall_rules': [{'IPProtocol': 'tcp'}],
            },
            {
                'firewall_rules': [{'IPProtocol': 'all'}],
            },
            True,
        ),
        (
            {
                'firewall_rules': [{'IPProtocol': 'all'}],
            },
            {
                'firewall_rules': [{'IPProtocol': 'tcp'}],
            },
            False,
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            {
                'firewall_rules': [{'IPProtocol': 'all'}],
            },
            True,
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            False,
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            True,
        ),
    ])
    def test_lt(self, action_1_dict, action_2_dict, expected):
        """Tests that action 1 < action 2 returns the correct value."""
        action_1 = firewall_rule.FirewallAction(**action_1_dict)
        action_2 = firewall_rule.FirewallAction(**action_2_dict)
        self.assertEqual(expected, action_1 < action_2)

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            True,
        ),
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            False,
        ),
        (
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22', '21', '20']},
                    ],
            },
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['21', '22', '23']},
                    ],
            },
            False,
        ),
        (
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'udp', 'ports': ['49-55']},
                        {'IPProtocol': 'tcp', 'ports': ['22', '21', '23']},
                    ],
            },
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['22-23']},
                        {'IPProtocol': 'udp', 'ports': ['50', '55']},
                    ],
            },
            True,
        ),
        (
            {
                'firewall_rules': [{'IPProtocol': 'tcp'}],
            },
            {
                'firewall_rules': [{'IPProtocol': 'all'}],
            },
            False,
        ),
        (
            {
                'firewall_rules': [{'IPProtocol': 'all'}],
            },
            {
                'firewall_rules': [{'IPProtocol': 'tcp'}],
            },
            True,
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            {
                'firewall_rules': [{'IPProtocol': 'all'}],
            },
            False,
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            True,
        ),
        (
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['22']}],
            },
            {
                'firewall_rules': [
                    {'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            False,
        ),
    ])
    def test_gt(self, action_1_dict, action_2_dict, expected):
        """Tests that action 1 > action 2 returns the correct value."""
        action_1 = firewall_rule.FirewallAction(**action_1_dict)
        action_2 = firewall_rule.FirewallAction(**action_2_dict)
        self.assertEqual(expected, action_1 > action_2)

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            {
                'firewall_rule_action': 'denied',
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['22', '21', '23']}],
            },
            False,
        ),
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp'}],
            },
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp'}, {'IPProtocol': 'udp'}],
            },
            False,
        ),
        (
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}],
            },
            {
                'firewall_rules':
                    [{'IPProtocol': 'tcp', 'ports': ['22', '21', '23']}],
            },
            True,
        ),
        (
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'tcp', 'ports': ['21-23']},
                        {'IPProtocol': 'udp', 'ports': ['55', '56', '58-60']},
                    ],
            },
            {
                'firewall_rules':
                    [
                        {'IPProtocol': 'udp', 'ports': [
                            '55-56', '58', '59', '60']},
                        {'IPProtocol': 'tcp', 'ports': ['22', '21', '23']}
                    ],
            },
            True,
        ),
    ])
    def test_is_equivalent(
            self, action_1_dict, action_2_dict, expected):
        """Tests that action 1 > action 2 returns the correct value."""
        action_1 = firewall_rule.FirewallAction(**action_1_dict)
        action_2 = firewall_rule.FirewallAction(**action_2_dict)
        self.assertEqual(expected, action_1.is_equivalent(action_2))

if __name__ == '__main__':
    unittest.main()
