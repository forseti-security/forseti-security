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
import mock
import unittest
import json
import parameterized

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.gcp_type import firewall_rule

class FirewallRuleTest(ForsetiTestCase):
    """Tests for firewall_rule."""

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
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_priority': 'NaN',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_priority': '-1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_priority': '1000000000',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
    ])
    def test_validate_priority_error(self, rule_dict):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaises(firewall_rule.InvalidFirewallRuleError):
            rule._validate_priority()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_destination_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_destination_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_source_tags': json.dumps(['t1']),
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'egress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
    ])
    def test_validate_direction_error(self, rule_dict):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaises(firewall_rule.InvalidFirewallRuleError):
            rule._validate_direction()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_network': 'n1',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
        (
            {
                'firewall_rule_name': 'n1',
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
        ),
    ])
    def test_validate_keys_error(self, rule_dict):
        rule = firewall_rule.FirewallRule(**rule_dict)
        with self.assertRaises(firewall_rule.InvalidFirewallRuleError):
            rule._validate_keys()

    @parameterized.parameterized.expand([
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['50-55']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['40-60']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            False,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_action': 'deny',
                'firewall_rule_denied': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            False,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*'])
            },
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.2']),
                'firewall_rule_direction': 'ingress',
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
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['21-23']}]),
            },
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
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.1']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['10.0.0.2']),
                'firewall_rule_direction': 'ingress',
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
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
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
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
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
                'firewall_rule_direction': 'ingress',
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
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n2',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t3', 't2']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't5']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            False,
        ),
        (
            {
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'ingress',
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
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_source_tags': json.dumps(['t1', 't2']),
                'firewall_rule_target_tags': json.dumps(['t3', 't4']),
                'firewall_rule_destination_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_direction': 'ingress',
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
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['22']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['10', '11', '12', '13']}]),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(
                    [{'IPProtocol': 'tcp', 'ports': ['10-13']}]),
            },
            True,
        ),
        (
            {
                'firewall_rule_source_ranges': json.dumps(['0.0.0.0/0']),
                'firewall_rule_direction': 'ingress',
                'firewall_rule_network': 'n1',
                'firewall_rule_allowed': json.dumps(['*']),
            },
            {
                'firewall_rule_source_ranges': json.dumps(['1.1.1.1']),
                'firewall_rule_direction': 'ingress',
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


class FirewallActionTest(ForsetiTestCase):
    """Tests for FirewallAction."""

    @parameterized.parameterized.expand([
        [{
            'firewall_rules': [{}],
        }],
        [{
            'firewall_rules':
            [
                {'IPProtocol': 'tcp', 'ports': ['21-23']},
                {},
            ],
        }],
    ])
    def test_validate_errors(self, action_1_dict):
        action = firewall_rule.FirewallAction(**action_1_dict)
        with self.assertRaises(firewall_rule.InvalidFirewallActionError):
          action.validate()

    @parameterized.parameterized.expand([
        [{
            'firewall_rules': [{}],
        }],
        [{
            'firewall_rules': [
                {'IPProtocol': 'tcp', 'ports': ['21-23']},
                {},
            ],
        }],
    ])
    def test_json_key_errors(self, action_dict):
        action = firewall_rule.FirewallAction(**action_dict)
        with self.assertRaises(firewall_rule.InvalidFirewallActionError):
          action.json_key()

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
    def test_json_key(self, action_dict, direction):
        action = firewall_rule.FirewallAction(**action_dict)
        key, value = action.json_key()
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
                'firewall_rule_action': 'deny',
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
