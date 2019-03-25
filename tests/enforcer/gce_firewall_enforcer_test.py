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

"""Tests for google.cloud.forseti.enforcer.gce_firewall_enforcer."""

import copy
import json
import threading
import unittest
import mock

from googleapiclient import errors
import parameterized

from tests.enforcer import testing_constants as constants
from tests.unittest_utils import ForsetiTestCase

from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.enforcer import gce_firewall_enforcer as fe

class HelperFunctionTest(ForsetiTestCase):
    """Unit tests for helper functions."""

    def test_get_network_name_from_url(self):
        """Verify that we can get the network name given a network url."""
        url = ('https://www.googleapis.com/compute/{}/projects/'
               'example.com:testing/global/networks/'
               'expected-network').format(fe.API_VERSION)
        self.assertEqual('expected-network',
                         fe.get_network_name_from_url(url))

    def test_build_network_url(self):
        """Verify that we can get a url from project and network name."""
        self.assertEqual('https://www.googleapis.com/compute/{}/projects/'
                         'example.com:testing/global/networks/'
                         'mytestnet'.format(fe.API_VERSION),
                         fe.build_network_url('example.com:testing',
                                              'mytestnet'))

    def test_is_successful(self):
        """_is_successful should know about bad responses and OK responses."""
        self.assertTrue(
            fe._is_successful({
                'kind': 'compute#operation'
            }))
        self.assertFalse(
            fe._is_successful({
                'error': {
                    'errors': [{
                        'code': 'NOT_FOUND'
                    }]
                }
            }))

        # We ignore the following errors:
        # RESOURCE_ALREADY_EXISTS: Because another program somewhere else
        #     could have already added the rule.
        # INVALID_FIELD_VALUE: Because the network probably disappeared
        #     out from under us.
        self.assertTrue(
            fe._is_successful({
                'error': {
                    'errors': [{
                        'code': 'RESOURCE_ALREADY_EXISTS'
                    }]
                }
            }))

        self.assertTrue(
            fe._is_successful({
                'error': {
                    'errors': [{
                        'code': 'INVALID_FIELD_VALUE'
                    }]
                }
            }))


class FirewallRulesTest(ForsetiTestCase):
    """Tests for the FirewallRules class."""

    def setUp(self):
        """Set up."""
        self.firewall_rules = fe.FirewallRules(constants.TEST_PROJECT)

    def test_add_rule_for_an_invalid_rule_type(self):
        """Validate that invalid rules raises an exception.

        Setup:
          * Knowing that add_rule is expecting a dict

        Expected Results:
          * add_rules should raise InvalidFirewallRuleError
        """
        rule_types_to_try = [[], '', 1]

        for rule in rule_types_to_try:
          with self.assertRaises(fe.InvalidFirewallRuleError) as r:
              self.firewall_rules.add_rule(
                  rule, network_name=constants.TEST_NETWORK)

    def test_add_rules_from_api(self):
        """Validate that add_rules_from_api adds appropriate rules.

        Setup:
          * Break the mock current firewall rules into two pages to validate
            nextPageToken works as expected.
          * Set compute.firewalls().list() to return to two pages of data.

        Expected Results:
          * Imported rules were successfully added to the rules dictionary.
        """
        mock_compute_client = mock.Mock(spec=compute.ComputeClient)

        mock_compute_client.get_firewall_rules.return_value = (
            constants.EXPECTED_FIREWALL_API_RESPONSE)

        self.firewall_rules.add_rules_from_api(mock_compute_client)

        self.assertSameStructure(constants.EXPECTED_FIREWALL_RULES,
                                 self.firewall_rules.rules)

    def test_add_rules_from_api_add_rule_false(self):
        """Validate function adds no rules when callback returns false.

        Setup:
          * Break the mock current firewall rules into two pages to validate
            nextPageToken works as expected
          * Set compute.firewalls().list() to return to two pages of data
          * Set _add_rule_callback to return False

        Expected Results:
          * No rules were added to the rules dictionary
        """
        mock_compute_client = mock.Mock(spec=compute.ComputeClient)
        mock_compute_client.get_firewall_rules.return_value = (
            constants.EXPECTED_FIREWALL_API_RESPONSE)

        self.firewall_rules._add_rule_callback = lambda _: False
        self.firewall_rules.add_rules_from_api(mock_compute_client)
        self.assertEqual({}, self.firewall_rules.rules)

    def test_add_rules_from_api_add_rule(self):
        """Validate that add_rules_from_api adds appropriate rules.

        Setup:
          * Break the mock current firewall rules into two pages to validate
            nextPageToken works as expected
          * Set compute.firewalls().list() to return to two pages of data
          * Set _add_rule_callback to only return True for specific rules.

        Expected Results:
          * Imported rules were successfully added to the rules dictionary
        """
        mock_compute_client = mock.Mock(spec=compute.ComputeClient)
        mock_compute_client.get_firewall_rules.return_value = (
            constants.EXPECTED_FIREWALL_API_RESPONSE)

        callback = lambda rule: (rule['name'] ==
                                 'test-network-allow-internal-1')

        self.firewall_rules._add_rule_callback = callback
        self.firewall_rules.add_rules_from_api(mock_compute_client)
        expected = {'test-network-allow-internal-1':
                    constants.EXPECTED_FIREWALL_RULES[
                        'test-network-allow-internal-1']}
        self.assertSameStructure(
            expected,
            self.firewall_rules.rules)

    def test_add_rules_for_network(self):
        """Validate adding rules for a specific network.

        Setup:
          * Load a raw policy from a JSON string.
          * Import the raw policy for a specific network.

        Expected Results:
          * Imported rules have the correct names and the correct network
            assigned.
        """
        test_rules = json.loads(constants.RAW_EXPECTED_JSON_POLICY)

        self.firewall_rules.add_rules(
            test_rules, network_name=constants.TEST_NETWORK)
        self.assertSameStructure(constants.EXPECTED_FIREWALL_RULES,
                                 self.firewall_rules.rules)

    def test_add_rules_for_network_long_name(self):
        """Validate adding rules for a specific network with a long name.

        Setup:
          * Load a sample firewall policy.
          * Set the test network name to a 63 character string.
          * Import the policy for the test network.

        Expected Results:
          * Imported rules have the correct name, with the network name
            truncated.
        """
        test_rules = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        test_network = 'x' * 63

        self.firewall_rules.add_rules(test_rules, network_name=test_network)
        expected_rule_names = [
            'x' * (62 - len(rule['name'])) + '-' + rule['name']
            for rule in test_rules
        ]
        self.assertItemsEqual(expected_rule_names,
                              self.firewall_rules.rules.keys())

    def test_add_rules_for_network_long_name_duplicate_rule(self):
        """Validate adding rules for two networks with similar long names.

        Setup:
          * Load a sample firewall policy.
          * Create three test networks with long names differing in the last
            character.
          * Import the policy for all test networks.

        Expected Results:
          * The second rule and third rules, which would have a duplicate name,
            have their names changed to a hash of the original network name.
        """
        test_rules = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        test_rules = test_rules[:1]

        rule_name = test_rules[0]['name']
        test_networks = ['x' * 62 + str(i) for i in range(3)]

        for network in test_networks:
            self.firewall_rules.add_rules(test_rules, network_name=network)

        expected_rule_names = []

        # test_networks[0], no hash
        expected_rule_names.append('x' * (62 - len(rule_name)) + '-' +
                                   rule_name)

        # test_networks[1], use hashed name
        expected_rule_names.append('hn-' + fe.hashlib.md5(test_networks[1])
                                   .hexdigest() + '-' + rule_name)

        # test_networks[2], use hashed name
        expected_rule_names.append('hn-' + fe.hashlib.md5(test_networks[2])
                                   .hexdigest() + '-' + rule_name)

        self.assertItemsEqual(expected_rule_names,
                              self.firewall_rules.rules.keys())

    def test_add_rules_for_network_is_idempotent(self):
        """Adding rules for a specific network doesn't modify the original.

        Setup:
          * Load a raw policy from a JSON string.
          * Make a deep copy of the raw policy object.
          * Import the raw policy for a specific network.

        Expected Results:
          * raw policy object is still equal to its deep copy.
        """
        test_rules = json.loads(constants.RAW_EXPECTED_JSON_POLICY)

        copy_of_test_rules = copy.deepcopy(test_rules)

        self.firewall_rules.add_rules(
            test_rules, network_name=constants.TEST_NETWORK)
        self.assertSameStructure(test_rules, copy_of_test_rules)

    def test_add_rules_for_network_negative_match(self):
        """Adding rules for a specific network skips rules on other networks.

        Setup:
          * Create a copy of rules for network 'test-network'.
          * Import the rules with a restriction of matching network 'default'.

        Expected Results:
          * No rules are added.
        """
        test_rules = constants.EXPECTED_FIREWALL_RULES.values()
        test_network = 'default'

        self.firewall_rules.add_rules(test_rules, network_name=test_network)
        self.assertEqual({}, self.firewall_rules.rules)

    def test_get_rules_for_network(self):
        """Validate get_rules_for_network returns a valid FirewallRules object.

        Setup:
          * Load a raw policy from a JSON string.
          * Import the raw policy for two different networks.
          * Run get_rules_for_network to return a new object with just the rules
            for one of the networks.

        Expected Results:
          * New FirewallRules object will have the correct rules.
        """
        test_rules = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        test_networks = ['default', constants.TEST_NETWORK]

        for network in test_networks:
            self.firewall_rules.add_rules(test_rules, network_name=network)

        expected_firewall_rules = fe.FirewallRules(constants.TEST_PROJECT)
        expected_firewall_rules.add_rules(
            test_rules, network_name=constants.TEST_NETWORK)

        # Validate that the current rules do not equal the expected rules
        self.assertNotEqual(expected_firewall_rules, self.firewall_rules)

        new_firewall_rules = self.firewall_rules.filtered_by_networks(
            [constants.TEST_NETWORK])
        self.assertEqual(expected_firewall_rules.rules, new_firewall_rules)

    def test_export_and_import_of_rules(self):
        """Validate that exported and imported rules match the original rules.

        Setup:
          * Add EXPECTED_FIREWALL_RULES to a FirewallRules object.
          * Export the rules to a JSON string.
          * Import the string into a new FirewallRules object.

        Expected Results:
          * The two FirewallRules objects are equal.
        """
        test_rules = constants.EXPECTED_FIREWALL_RULES.values()
        self.firewall_rules.add_rules(test_rules)

        json_rules = self.firewall_rules.as_json()
        new_firewall_rules = fe.FirewallRules(constants.TEST_PROJECT)
        new_firewall_rules.add_rules_from_json(json_rules)

        self.assertEqual(self.firewall_rules, new_firewall_rules)


class FirewallRulesCheckRuleTest(ForsetiTestCase):
    """Multiple tests for FirewallRules._check_rule_before_adding."""

    def setUp(self):
        """Set up."""
        self.firewall_rules = fe.FirewallRules(constants.TEST_PROJECT)

        self.test_rule = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-1'])

    def test_valid(self):
        """Verify valid rules returns True."""
        self.assertTrue(
            self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_valid_callback_false(self):
        """Verify valid rules returns True."""
        self.firewall_rules._add_rule_callback = lambda _: False
        self.assertFalse(
            self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_unknown_key(self):
        """A rule with an unknown key raises InvalidFirewallRuleError."""
        self.test_rule['unknown'] = True
        with self.assertRaises(fe.InvalidFirewallRuleError) as r:
            self.firewall_rules._check_rule_before_adding(self.test_rule)

        self.assertEqual(
            'An unexpected entry exists in a firewall rule dict: "unknown".',
            str(r.exception))

    def test_missing_required_key(self):
        """A rule missing a required key raises InvalidFirewallRuleError."""
        for key in ['allowed', 'name', 'network']:
            test_rule = copy.deepcopy(self.test_rule)
            test_rule.pop(key)
            with self.assertRaises(fe.InvalidFirewallRuleError):
                self.firewall_rules._check_rule_before_adding(test_rule)

    def test_missing_ip_protocol(self):
        """Rule missing IPProtocol in an allow predicate raises an exception."""
        self.test_rule['allowed'][0].pop('IPProtocol')
        with self.assertRaises(fe.InvalidFirewallRuleError):
            self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_denied_missing_ip_protocol(self):
      """A rule missing IPProtocol in an denied predicate raises an
         exception."""
      allowed = self.test_rule.pop('allowed')
      self.test_rule['denied'] = allowed
      self.test_rule['denied'][0].pop('IPProtocol')
      with self.assertRaises(fe.InvalidFirewallRuleError):
        self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_long_name(self):
        """A rule with a very long name raises InvalidFirewallRuleError."""
        # Make rule name 64 characters long
        self.test_rule['name'] = 'long-name-' + 'x' * 54
        with self.assertRaises(fe.InvalidFirewallRuleError):
            self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_duplicate_rule_name(self):
        """A rule with the same name as an existing rule raises an exception.

        Setup:
          * Add test_rule to the firewall_rules object.
          * Set new_rule to a different rule from the EXPECTED_FIREWALL_RULES
            policy.
          * Update new_rule to have the same name as test_rule.
          * Run _check_rule_before_adding on new_rule.

        Expected Results:
          * DuplicateFirewallRuleNameError exception is raised.
        """
        self.firewall_rules.add_rule(self.test_rule)

        new_rule = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0'])
        new_rule['name'] = self.test_rule['name']
        with self.assertRaises(fe.DuplicateFirewallRuleNameError):
            self.firewall_rules._check_rule_before_adding(new_rule)

    def test_allowed_and_denied(self):
      """A rule with allowed and denied ports raises
         InvalidFirewallRuleError."""
      self.test_rule['denied'] = [{'IPProtocol': u'udp'}]
      with self.assertRaises(fe.InvalidFirewallRuleError):
        self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_denied_rule(self):
      """A rule with denied ports returns True."""
      allowed = self.test_rule.pop('allowed')
      self.test_rule['denied'] = allowed
      self.assertTrue(
          self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_direction_ingress(self):
      """A rule with direction set to INGRESS returns True."""
      self.test_rule['direction'] = 'INGRESS'
      self.assertTrue(
          self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_direction_egress_source_ranges(self):
      """Rule with direction set to EGRESS with sourceRanges raises
         exception."""
      self.test_rule['direction'] = 'EGRESS'
      with self.assertRaises(fe.InvalidFirewallRuleError):
        self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_direction_egress_destination_ranges(self):
      """Rule with direction set to EGRESS with destinationRanges returns
         True."""
      self.test_rule['direction'] = 'EGRESS'
      source_ranges = self.test_rule.pop('sourceRanges')
      self.test_rule['destinationRanges'] = source_ranges
      self.assertTrue(
          self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_invalid_direction(self):
      """Rule with direction set to invalid raises exception."""
      self.test_rule['direction'] = 'INVALID'
      with self.assertRaises(fe.InvalidFirewallRuleError):
        self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_source_and_destination_ranges(self):
      """Rule with sourceRanges and destinationRanges raises exception."""
      self.test_rule['destinationRanges'] = copy.deepcopy(
          self.test_rule['sourceRanges'])
      with self.assertRaises(fe.InvalidFirewallRuleError):
        self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_priority(self):
      """Rule with priority set returns True."""
      self.test_rule['priority'] = '1000'
      self.assertTrue(
          self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_invalid_priority(self):
      """Rule with priority set to invalid raises exception."""
      self.test_rule['priority'] = 'INVALID'
      with self.assertRaises(fe.InvalidFirewallRuleError):
        self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_invalid_priority_out_of_range(self):
      """Rule with priority set to an out of range value raises exception."""
      invalid_values = ['-1', '65536']
      for priority in invalid_values:
        self.test_rule['priority'] = priority
        with self.assertRaises(fe.InvalidFirewallRuleError):
          self.firewall_rules._check_rule_before_adding(self.test_rule)

    def test_keys_with_more_than_256_values(self):
      """Rule entries with more than 256 values raises an exception."""
      ingress_keys = set(['sourceRanges', 'sourceTags', 'targetTags'])
      for key in ingress_keys:
        new_rule = copy.deepcopy(self.test_rule)
        new_rule['direction'] = 'INGRESS'
        new_rule[key] = range(257)
        with self.assertRaises(fe.InvalidFirewallRuleError):
          self.firewall_rules._check_rule_before_adding(new_rule)

      egress_keys = set(['destinationRanges'])
      for key in egress_keys:
        new_rule = copy.deepcopy(self.test_rule)
        new_rule['direction'] = 'EGRESS'
        new_rule[key] = range(257)
        with self.assertRaises(fe.InvalidFirewallRuleError):
          self.firewall_rules._check_rule_before_adding(new_rule)


class FirewallEnforcerTest(constants.EnforcerTestCase):
    """Tests for the FirewallEnforcer class."""

    def setUp(self):
        """Set up.

        Creates a FirewallEnforcer object with current and expected rules set to
        an empty FirewallRules object.
        """
        super(FirewallEnforcerTest, self).setUp()

        self.expected_rules = fe.FirewallRules(constants.TEST_PROJECT)
        self.current_rules = fe.FirewallRules(constants.TEST_PROJECT)

        self.project_sema = threading.BoundedSemaphore(value=1)

        self.enforcer = fe.FirewallEnforcer(
            constants.TEST_PROJECT, self.gce_api_client, self.expected_rules,
            self.current_rules, self.project_sema, None)

    def test_apply_firewall_no_changes(self):
        """No changes when current and expected rules match."""
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES
        self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES

        changed_count = self.enforcer.apply_firewall()
        self.assertEqual(0, changed_count)

    def test_apply_firewall_no_rules(self):
        """Raises exception if no expected_rules defined."""
        with self.assertRaises(fe.EmptyProposedFirewallRuleSetError):
            self.enforcer.apply_firewall()

    def test_apply_firewall_allow_empty_ruleset(self):
        """Deletes all current rules if allow_empty_ruleset is true.

        Setup:
          * Set current_rules to EXPECTED_FIREWALL_RULES.
          * Leave expected_rules with no rules defined.
          * Run self.enforcer.apply_firewall with allow_empty_ruleset set to
            true.

        Expected Results:
          * The current rules are deleted, no rules inserted or updated.
        """
        self.current_rules.add_rules(constants.EXPECTED_FIREWALL_RULES.values())

        changed_count = self.enforcer.apply_firewall(allow_empty_ruleset=True)

        self.assertEqual(len(self.current_rules.rules), changed_count)
        self.assertSameStructure(
            sorted(self.enforcer.current_rules.rules.values()),
            sorted(self.enforcer.get_deleted_rules()))
        self.assertEqual([], self.enforcer.get_inserted_rules())
        self.assertEqual([], self.enforcer.get_updated_rules())

    def test_apply_firewall_all_rules_differ_single_network(self):
        """Validate apply_firewall works end to end with no errors.

        Setup:
          * Set expected_policy to RAW_EXPECTED_JSON_POLICY.
          * Set expected_rules to expected_policy for network TEST_NETWORK.
          * Set compute.firewalls().list() to return
            DEFAULT_FIREWALL_API_RESPONSE.
          * Set current_rules to None so ApplyFirewall will query the compute
            API.
          * Run FirewallEnforcer.apply_firewall() with networks set to
            TEST_NETWORKS.

        Expected Results:
          * apply_firewall will return a changed_count of 7 rules
            (3 added, 4 removed).
          * get_deleted_rules will return a list containing the rule from
            current_rules.
          * get_inserted_rules will return a list containing all the rules from
            expected_rules.
          * get_updated_rules will return an empty list.
        """
        expected_policy = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        self.expected_rules.add_rules(
            expected_policy, network_name=constants.TEST_NETWORK)

        self.gce_api_client.get_firewall_rules.return_value = (
            constants.DEFAULT_FIREWALL_API_RESPONSE)

        self.enforcer.current_rules = None

        changed_count = self.enforcer.apply_firewall(
            networks=[constants.TEST_NETWORK])

        self.assertEqual(7, changed_count)

        self.assertSameStructure(
            sorted(self.enforcer.current_rules.rules.values()),
            sorted(self.enforcer.get_deleted_rules()))

        self.assertSameStructure(
            sorted(self.expected_rules.rules.values()),
            sorted(self.enforcer.get_inserted_rules()))

        self.assertEqual([], self.enforcer.get_updated_rules())

    def test_apply_firewall_multiple_changes(self):
        """Validate apply_firewall works with multiple different rule changes.

        Setup:
          Set EXPECTED_FIREWALL_RULES as the enforced policy.

          Modify the mock current firewall rules as follows:
            1. No change to test-network-allow-internal-1.
            2. Add a new source range to test-network-allow-internal-0.
            3. Remove test-network-allow-public-0.
            4. Add a new fake rule unknown-rule-doesnt-match.

        Expected Results:
          * apply_firewall will return a changed_count of 3 rules.
          * get_deleted_rules will return unknown-rule-doesnt-match.
          * get_inserted_rules will return test-network-allow-public-0.
          * get_updated_rules will return test-network-allow-internal-0.
        """
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        # All four of these cases should be tested:
        # Rule zero, we'll leave alone and allow it to match.  It should
        # neither be removed nor added.
        rule_zero = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-1'])
        self.current_rules.add_rule(rule_zero)

        # Rule one, we'll modify so it needs to be updated.
        rule_one = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0'])
        rule_one['sourceRanges'].append('11.0.0.0/8')
        self.current_rules.add_rule(rule_one)

        # Rule two, we won't insert so that it gets re-added.
        rule_two = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-public-0'])

        # Rule three isn't part of EXPECTED_FIREWALL_RULES.It should be removed.
        rule_three = {
            'allowed': [{
                'IPProtocol': u'icmp'
            }, {
                'IPProtocol': u'udp',
                'ports': [u'1-65535']
            }],
            'description':
                u'Allow communication between instances.',
            'name':
                u'unknown-rule-doesnt-match',
            'network': (u'https://www.googleapis.com/compute/{}/projects/'
                        'example.com:testing/global/networks/'
                        'test-net').format(fe.API_VERSION),
            'sourceRanges': [u'10.2.3.4/32'],
            'logConfig': {'enable': False},
            'disabled': False,
            'priority': 1000,
            'direction': u'INGRESS'
        }
        self.current_rules.add_rule(rule_three)

        changed_count = self.enforcer.apply_firewall()

        self.assertEqual(3, changed_count)

        self.assertSameStructure([rule_three],
                                 self.enforcer.get_deleted_rules())

        self.assertSameStructure([rule_two], self.enforcer.get_inserted_rules())

        expected_updated_rule = (
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0'])
        self.assertSameStructure([expected_updated_rule],
                                 self.enforcer.get_updated_rules())

    def test_apply_firewall_prechange_callback_false(self):
        """Prechange callback that returns False stops changes from being made.

        Setup:
          Set EXPECTED_FIREWALL_RULES as the enforced policy.

          Modify the mock current firewall rules as follows:
            1. Add a new source range to test-network-allow-internal-0.

          Create a callback function that always returns False.

        Expected Results:
          * apply_firewall will return a changed_count of 0 rules.
          * get_updated_rules will return an empty list.
          * The internal attribute _rules_to_update contains
            test-network-allow-internal-0.
        """
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        # Add rules to current_rules
        rules = ['test-network-allow-internal-1', 'test-network-allow-public-0']
        for rule in rules:
            new_rule = copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[rule])
            self.current_rules.add_rule(new_rule)

        # Rule test-net-allow-corp-internal-0 is modified, it needs to be
        # updated.
        rule_one = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0'])
        rule_one['sourceRanges'].append('11.0.0.0/8')
        self.current_rules.add_rule(rule_one)

        prechange_callback_func = lambda *args: False

        changed_count = self.enforcer.apply_firewall(
            prechange_callback=prechange_callback_func)
        self.assertEqual(0, changed_count)
        self.assertEqual([], self.enforcer.get_updated_rules())
        self.assertEqual(['test-network-allow-internal-0'],
                         self.enforcer._rules_to_update)

    def test_apply_firewall_prechange_callback_true(self):
        """A prechange callback that returns True allows changes to be made.

        Setup:
          Set EXPECTED_FIREWALL_RULES as the enforced policy.

          Modify the mock current firewall rules as follows:
            1. Add a new source range to test-network-allow-internal-0.

          Create a callback function that always returns True.

        Expected Results:
          * apply_firewall will return a changed_count of 1 rules.
          * get_updated_rules will return test-network-allow-internal-0.
        """
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        # Add rules to current_rules
        rules = ['test-network-allow-internal-1', 'test-network-allow-public-0']
        for rule in rules:
            new_rule = copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[rule])
            self.current_rules.add_rule(new_rule)

        # Rule test-net-allow-corp-internal-0 is modified, it needs to be
        # updated.
        rule_one = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0'])
        rule_one['sourceRanges'].append('11.0.0.0/8')
        self.current_rules.add_rule(rule_one)

        prechange_callback_func = lambda *args: True

        changed_count = self.enforcer.apply_firewall(
            prechange_callback=prechange_callback_func)
        self.assertEqual(1, changed_count)

        self.assertSameStructure(
            self.enforcer.get_updated_rules(),
            [constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0']]
        )

    def test_build_change_set_all_rules_differ_single_network(self):
        """Build a change set for a single network when all rules differ.

        Setup:
          * Set expected_rules to RAW_EXPECTED_JSON_POLICY on 'test-network' and
            'default' networks.
          * Set current_rules to RAW_DEFAULT_JSON_POLICY on 'test-network' and
            'default' networks.
          * Execute FirewallEnforcer._build_change_set(['test-network']).

        Expected Results:
          * All rules in current_rules for 'test-network' are in
            self.enforcer._rules_to_delete.
          * All rules in expected_rules for 'test-network' are in
            self.enforcer._rules_to_insert.
          * No rules in self.enforcer._rules_to_update.
        """
        expected_policy = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        self.expected_rules.add_rules(
            expected_policy, network_name=constants.TEST_NETWORK)
        self.expected_rules.add_rules(expected_policy, network_name='default')

        current_policy = json.loads(constants.RAW_DEFAULT_JSON_POLICY)
        self.current_rules.add_rules(
            current_policy, network_name=constants.TEST_NETWORK)
        self.current_rules.add_rules(current_policy, network_name='default')

        self.enforcer._build_change_set([constants.TEST_NETWORK])

        expected_deleted_rules = sorted(constants.DEFAULT_FIREWALL_RULES.keys())

        expected_inserted_rules = sorted(
            constants.EXPECTED_FIREWALL_RULES.keys())

        self.assertListEqual(expected_deleted_rules,
                             sorted(self.enforcer._rules_to_delete))

        self.assertListEqual(expected_inserted_rules,
                             sorted(self.enforcer._rules_to_insert))

        self.assertListEqual([], self.enforcer._rules_to_update)

    def test_build_change_set(self):
        """Verify output of FirewallEnforcer._build_change_set.

        Setup:
          Set EXPECTED_FIREWALL_RULES as the enforced policy.

          Modify the mock current firewall rules as follows:
            1. No change to test-network-allow-internal-0.
            2. Add a new source range to test-network-allow-internal-1.
            3. Remove test-network-allow-public-0.
            4. Add a new fake rule unknown-rule-doesnt-match.

        Expected results:
          * test-network-allow-public-0 in _rules_to_add list.
          * test-network-allow-internal-1 in _rules_to_update list.
          * unknown-rule-doesnt-match in _rules_to_delete list.
        """
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        # All four of these cases should be tested:
        # Rule zero, we'll leave alone and allow it to match.  It should
        # neither be removed nor added.
        rule_zero = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0'])
        self.current_rules.add_rule(rule_zero)

        # Rule one, we'll modify so it needs to be updated.
        rule_one = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-1'])
        rule_one['sourceRanges'].append('11.0.0.0/8')
        self.current_rules.add_rule(rule_one)

        # Rule two isn't part of EXPECTED_FIREWALL_RULES.  It should be
        # removed.
        rule_two = {
            'allowed': [{
                'IPProtocol': u'udp',
                'ports': [u'1-65535']
            }, {
                'IPProtocol': u'icmp'
            }],
            'description':
                u'Allow communication between instances.',
            'name':
                u'unknown-rule-doesnt-match',
            'network': (u'https://www.googleapis.com/compute/beta/projects/'
                        'forseti-system-test/global/networks/test-net'),
            'sourceRanges': [u'10.2.3.4/32'],
        }
        self.current_rules.add_rule(rule_two)

        self.enforcer._build_change_set()

        self.assertListEqual(['test-network-allow-public-0'],
                             self.enforcer._rules_to_insert)

        self.assertListEqual(['test-network-allow-internal-1'],
                             self.enforcer._rules_to_update)

        self.assertListEqual(['unknown-rule-doesnt-match'],
                             self.enforcer._rules_to_delete)

    def test_validate_change_set_insert_rule_exists(self):
        """Ensure validate_change_set raises exceptions on duplicate rules.

        Setup:
          * Set current_rules to EXPECTED_FIREWALL_RULES.
          * Set expected_rules to EXPECTED_FIREWALL_RULES.
          * Mock a _rules_to_insert list with a rule in EXPECTED_FIREWALL_RULES.
          * Run _validate_change_set with networks set to ['test-network'].

        Expected Results:
          A FirewallEnforcementFailedError exception will be raised
        """
        self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        # Insert a rule that is already defined in current_rules and not deleted
        self.enforcer._rules_to_insert.append('test-network-allow-internal-0')
        with self.assertRaises(fe.FirewallRuleValidationError):
            # ValidateChangeSet only checks rules if networks is not None
            self.enforcer._validate_change_set(
                networks=[constants.TEST_NETWORK])

    def test_validate_change_update_rule_modifies_wrong_network(self):
        """Raises exceptions when wrong network impacted.

        Setup:
          * Set current_rules to RAW_EXPECTED_JSON_POLICY on 'test-network' and
            'default' networks.
          * Set expected_rules to RAW_EXPECTED_JSON_POLICY on 'test-network' and
            'default' networks.
          * Mock a _rules_to_update list with a rule on the 'default' network.
          * Run _validate_change_set with networks set to ['test-network'].

        Expected Results:
          A FirewallEnforcementFailedError exception will be raised.
        """
        default_policy = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        self.expected_rules.add_rules(
            default_policy, network_name=constants.TEST_NETWORK)
        self.expected_rules.add_rules(default_policy, network_name='default')

        self.current_rules.add_rules(
            default_policy, network_name=constants.TEST_NETWORK)
        self.current_rules.add_rules(default_policy, network_name='default')

        # Update a rule that is defined in current_rules on a different network
        self.enforcer._rules_to_update.append('default-allow-internal-0')
        with self.assertRaises(fe.NetworkImpactValidationError):
            self.enforcer._validate_change_set(
                networks=[constants.TEST_NETWORK])

    def test_validate_change_update_rule_without_networks(self):
        """Do not raise exception when networks=None.

        Setup:
          * Set current_rules to RAW_EXPECTED_JSON_POLICY on 'test-network'
            network.
          * Set expected_rules to RAW_EXPECTED_JSON_POLICY on 'test-network'
            network.
          * Mock a _rules_to_update list with a rule on the 'test-network'
            network.
          * Run _validate_change_set.

        Expected Results:
          Method should return None with no exceptions.
        """
        default_policy = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        self.expected_rules.add_rules(
            default_policy, network_name=constants.TEST_NETWORK)

        self.current_rules.add_rules(
            default_policy, network_name=constants.TEST_NETWORK)

        # Update a rule that is defined in current_rules on a different network
        self.enforcer._rules_to_update.append('test-network-allow-internal-0')

        self.assertEqual(None, self.enforcer._validate_change_set())

    def test_apply_change(self):
        """Validate apply_change works with no errors."""
        delete_function = self.gce_api_client.delete_firewall_rule
        insert_function = self.gce_api_client.insert_firewall_rule
        update_function = self.gce_api_client.patch_firewall_rule

        test_rules = [
            copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[
                'test-network-allow-internal-0'])
        ]

        for function in [delete_function, insert_function, update_function]:
            (successes, failures, change_errors) = self.enforcer._apply_change(
                function, test_rules)
            self.assertSameStructure(test_rules, successes)
            self.assertListEqual([], failures)
            self.assertListEqual([], change_errors)

    def test_apply_change_no_rules(self):
        """Running apply_change with no rules returns empty lists."""
        delete_function = self.gce_api_client.delete_firewall_rule
        (successes, failures, change_errors) = self.enforcer._apply_change(
            delete_function, [])
        self.assertListEqual([], successes)
        self.assertListEqual([], failures)
        self.assertListEqual([], change_errors)

    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    def test_apply_change_insert_http_error(self, mock_logger):
        """Adds the rule to failures on HttpError exception.

        Setup:
          * Create a status 409 HttpError object.
          * Set insert_function to raise HttpError.
          * Run apply_change with fake insert_function.

        Expected Results:
          * Passed in rule ends up in failures list.
        """
        response = fe.httplib2.Response({
            'status': '409',
            'content-type': 'application/json'
        })
        response.reason = 'Duplicate Rule'
        error_409 = errors.HttpError(response, '', uri='')
        err = api_errors.ApiExecutionError(self.project, error_409)

        insert_function = mock.Mock(side_effect=err)

        test_rules = [
            copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[
                'test-network-allow-internal-0'])
        ]

        (successes, failures, change_errors) = self.enforcer._apply_change(
            insert_function, test_rules)
        self.assertSameStructure(test_rules, failures)
        self.assertListEqual([], successes)
        error_str = 'Rule: %s\nError: %s' % (
            test_rules[0].get('name', ''),
            err)
        self.assertListEqual([error_str], change_errors)
        self.assertTrue(mock_logger.exception.called)

    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    def test_apply_change_operation_status_error(self, mock_logger):
        """Adds the rule to failures on HttpError exception.

        Setup:
          * Create a mock _create_dry_run_response method.
          * Set _create_dry_run_response to return an error response for all
            operations.
          * Run apply_change.

        Expected Results:
          * Passed in rule ends up in failures list.
        """
        insert_function = self.gce_api_client.insert_firewall_rule

        test_rules = [
            copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[
                'test-network-allow-internal-0'])
        ]
        with mock.patch.object(
                repository_mixins, '_create_fake_operation') as mock_dry_run:

            mock_dry_run.return_value = {
                'status': 'DONE',
                'name': 'test',
                'error': {
                    'errors': [{
                        'code': 'ERROR'
                    }]
                }
            }
            (successes, failures, change_errors) = self.enforcer._apply_change(
                insert_function, test_rules)

        self.assertSameStructure(test_rules, failures)
        self.assertListEqual([], successes)
        self.assertListEqual([], change_errors)
        self.assertTrue(mock_logger.error.called)

    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    def test_apply_change_operation_timeout_error(self, mock_logger):
        """Adds the rule to failures on Operation Timeout exception.

        Setup:
          * Mock insert_firewall_rule to return OperationTimeoutError
          * Run apply_change.

        Expected Results:
          * Passed in rule ends up in failures list.
        """
        test_rules = [
            copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[
                'test-network-allow-internal-0'])
        ]
        with mock.patch.object(
                self.gce_api_client, 'insert_firewall_rule') as mock_insert:

            mock_operation = {
                'kind': 'compute#operation',
                'id': '1234',
                'name': 'operation-1234',
                'operationType': 'insert',
                'targetLink': ('https://www.googleapis.com/compute/v1/projects/'
                               'test-project/global/firewalls/'
                               'test-network-allow-internal-0'),
                'targetId': '123456',
                'status': 'PENDING',
                'user': 'mock_data@example.com',
                'progress': 0,
                'insertTime': '2018-08-02T06:49:34.713-07:00',
                'selfLink': ('https://www.googleapis.com/compute/v1/projects/'
                             'test-project/global/operations/operation-1234')
            }
            err = api_errors.OperationTimeoutError(self.project, mock_operation)
            mock_insert.side_effect = err
            (successes, failures, change_errors) = self.enforcer._apply_change(
                mock_insert, test_rules)

        self.assertSameStructure(test_rules, failures)
        self.assertListEqual([], successes)
        error_str = 'Rule: %s\nError: %s' % (
            test_rules[0].get('name', ''),
            err)
        self.assertListEqual([error_str], change_errors)
        self.assertTrue(mock_logger.exception.called)

    def test_apply_changes(self):
        """Validate _apply_change_set works with no errors.

        Setup:
          * Set current and expected rules to EXPECTED_FIREWALL_RULES.
          * Add one rule each to rules_to_(delete|insert|update).
          * Run _apply_change_set with network set to None

        Expected Results:
          * _apply_change_set will return 3 for the number of rules changed.
          * The methods get_(deleted|inserted|updated)_rules() will each return
            a list containing the rules that were (deleted|inserted|updated) by
            _apply_changes.
        """
        self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        self.enforcer._rules_to_delete = ['test-network-allow-internal-1']
        self.enforcer._rules_to_insert = ['test-network-allow-internal-0']
        self.enforcer._rules_to_update = ['test-network-allow-public-0']

        delete_before_insert = False

        changed_count = self.enforcer._apply_change_set(delete_before_insert,
                                                        None)

        self.assertSameStructure([
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-1']
        ], self.enforcer.get_deleted_rules())

        self.assertSameStructure([
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0']
        ], self.enforcer.get_inserted_rules())

        self.assertSameStructure(
            [constants.EXPECTED_FIREWALL_RULES['test-network-allow-public-0']],
            self.enforcer.get_updated_rules())

    def test_apply_changes_single_network(self):
        """Validate _apply_change_set works on a single network.

        Setup:
          * Set expected_policy to RAW_EXPECTED_JSON_POLICY.
          * Set expected_rules to expected_policy for networks 'default' and
            TEST_NETWORK.
          * Set current_rules to expected_policy for networks 'default' and
            TEST_NETWORK.
          * Add one rule for each network to each of
            rules_to_(delete|insert|update).
          * Run _apply_change_set with network set to 'default'

        Expected Results:
          * Only rules on network 'default' are in the results for
            get_(deleted|inserted|updated)_rules().
        """
        expected_policy = json.loads(constants.RAW_EXPECTED_JSON_POLICY)
        self.expected_rules.add_rules(
            expected_policy, network_name=constants.TEST_NETWORK)
        self.expected_rules.add_rules(
            expected_policy, network_name='default')
        self.current_rules.add_rules(
            expected_policy, network_name=constants.TEST_NETWORK)
        self.current_rules.add_rules(
            expected_policy, network_name='default')

        self.enforcer._rules_to_delete = [
            'test-network-allow-internal-1', 'default-allow-internal-1']
        self.enforcer._rules_to_insert = [
            'test-network-allow-internal-0', 'default-allow-internal-0']
        self.enforcer._rules_to_update = [
            'test-network-allow-public-0', 'default-allow-public-0']

        delete_before_insert = False

        changed_count = self.enforcer._apply_change_set(delete_before_insert,
                                                        'default')
        expected_changed_count = 3

        self.assertEqual(expected_changed_count, changed_count)

        self.assertSameStructure(
            [self.expected_rules.rules['default-allow-internal-1']],
            self.enforcer.get_deleted_rules())

        self.assertSameStructure(
            [self.expected_rules.rules['default-allow-internal-0']],
            self.enforcer.get_inserted_rules())

        self.assertSameStructure(
            [self.expected_rules.rules['default-allow-public-0']],
            self.enforcer.get_updated_rules())

    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    def test_apply_changes_operation_status_error(self, mock_logger):
        """Validate that an error on a change raises the expected exception.

        Setup:
          * Set current and expected rules to EXPECTED_FIREWALL_RULES.
          * Create a mock _create_dry_run_response method.
          * Set _create_dry_run_response to return an error response for all
            operations.
          * Run _apply_changes three times, once to delete, once to insert and
            once to update, with network set to None.

        Expected Results:
          * Each time it is run, _apply_changes should raise a
            FirewallEnforcementFailedError exception.
          * get_(deleted|inserted|updated)_rules() should return an empty list.
        """
        self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        delete_before_insert = False

        self.enforcer._rules_to_delete = ['test-network-allow-internal-0']
        with mock.patch.object(
                repository_mixins, '_create_fake_operation') as mock_dry_run:

            mock_dry_run.return_value = {
                'status': 'DONE',
                'name': 'test',
                'error': {
                    'errors': [{
                        'code': 'NOT_FOUND'
                    }]
                }
            }
            with self.assertRaises(fe.FirewallEnforcementFailedError):
                self.enforcer._apply_change_set(delete_before_insert, None)

            self.assertEqual([], self.enforcer.get_deleted_rules())
            self.enforcer._rules_to_delete = []

            self.enforcer._rules_to_insert = ['test-network-allow-internal-0']
            with self.assertRaises(fe.FirewallEnforcementFailedError):
                self.enforcer._apply_change_set(delete_before_insert, None)
            self.assertEqual([], self.enforcer.get_inserted_rules())
            self.enforcer._rules_to_insert = []

            self.enforcer._rules_to_update = ['test-network-allow-internal-0']
            with self.assertRaises(fe.FirewallEnforcementFailedError):
                self.enforcer._apply_change_set(delete_before_insert, None)
            self.assertEqual([], self.enforcer.get_updated_rules())
            self.enforcer._rules_to_update = []

        self.assertTrue(mock_logger.error.called)

    def test_apply_changes_delete_first(self):
      """Validate _apply_change_set works with no errors.

      Setup:
        * Set current and expected rules to EXPECTED_CORP_FIREWALL_RULES
        * Add one rule each to rules_to_(delete|insert|update)
        * Set _delete_first to True
        * Run _apply_change_set with network set to None

      Expected Results:
        * _apply_change_set will return 3 for the number of rules changed
        * The methods Get(Deleted|Inserted|Updated)Rules() will each return a
          list containing the rules that were (deleted|inserted|updated) by
          _ApplyChanges.
      """

      self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES
      self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

      self.enforcer._rules_to_delete = ['test-network-allow-internal-1']
      self.enforcer._rules_to_insert = ['test-network-allow-internal-0']
      self.enforcer._rules_to_update = ['test-network-allow-public-0']

      delete_before_insert = True
      changed_count = self.enforcer._apply_change_set(delete_before_insert,
                                                      None)

      self.assertEqual(3, changed_count)

      self.assertSameStructure(self.enforcer.get_deleted_rules(),
                               [constants.EXPECTED_FIREWALL_RULES[
                                   'test-network-allow-internal-1']])

      self.assertSameStructure(self.enforcer.get_inserted_rules(),
                               [constants.EXPECTED_FIREWALL_RULES[
                                   'test-network-allow-internal-0']])

      self.assertSameStructure(self.enforcer.get_updated_rules(),
                               [constants.EXPECTED_FIREWALL_RULES[
                                   'test-network-allow-public-0']])

    @parameterized.parameterized.expand([
        ('no_quota', 0, 0, 1, 0, True, False),
        ('low_quota_1', 1, 1, 1, 0, True, False),
        ('low_quota_2', 10, 8, 4, 1, True, False),
        ('low_quota_3', 10, 8, 4, 2, False, True),
        ('high_quota_1', 100, 6, 10, 6, False, False),
        ('high_quota_2', 100, 85, 30, 50, False, True),
        ('unknown_quota', None, None, 1, 0, False, True)])
    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    @mock.patch('google.cloud.forseti.common.gcp_api.compute.LOGGER', autospec=True)
    def test_check_change_operation_order(self, name, quota, usage,
                                          insert_rule_count, delete_rule_count,
                                          expect_exception,
                                          expect_delete_before_insert,
                                          mock_logger_enforcer,
                                          mock_logger_compute):

        """Validate CheckChangeOperationOrder has expected behavior.

        Args:
          quota: The mocked firewall quota limit.
          usage: The mocked current firewall quota usage.
          insert_rule_count: The number of rules that would be inserted.
          delete_rule_count: The number of rules that would be deleted.
          expect_exception: True if an exception should be raised.
          expect_delete_before_insert: The expected return value from the check.

        Setup:
          * Mock project.get() to return a FIREWALLS quota with specific limits.
          * Mock the number of rules that would be inserted and/or deleted.

        Expected Results:
          * When mock project does not have enough quota, an exception is
            raised.
          * When mock project does not have enough quota to insert first and
            then
            delete, the method returns True.
          * When mock project does have enough quota, the method returns False.
        """
        if quota is not None:
          self.gce_api_client.get_project.return_value = {
              'quotas': [{'metric': 'FIREWALLS',
                          'limit': quota,
                          'usage': usage}]}
        else:
          self.gce_api_client.get_project.return_value = {
              'quotas': []}

        if expect_exception:
          with self.assertRaises(fe.FirewallQuotaExceededError):
            self.enforcer._check_change_operation_order(
                insert_rule_count, delete_rule_count)
        else:
          delete_before_insert = self.enforcer._check_change_operation_order(
              insert_rule_count, delete_rule_count)

          self.assertEqual(expect_delete_before_insert, delete_before_insert)


class FirewallRulesAreEqualTest(ForsetiTestCase):
    """Multiple tests for (in)equality between two firewall rules."""

    def setUp(self):
        """Start with two identical rules."""
        self.firewall_rules_1 = fe.FirewallRules(constants.TEST_PROJECT)
        self.firewall_rules_2 = fe.FirewallRules(constants.TEST_PROJECT)

        self.rule_one = {
            'network': ('https://www.googleapis.com/compute/{}/'
                        'projects/example.com:testing/global/networks/'
                        'default').format(fe.API_VERSION),
            'sourceRanges': ['10.240.0.0/16', '10.8.129.0/24'],
            'sourceTags': ['example-source-tag'],
            'allowed': [{
                'IPProtocol': 'udp',
                'ports': ['1-65535']
            }, {
                'IPProtocol': 'tcp',
                'ports': ['80', '443', '8080']
            }, {
                'IPProtocol': 'icmp'
            }],
            'description':
                'Allow communication between instances.',
            'name':
                u'test-network-allow-internal',
            'targetTags': ['example-target-tag']
        }
        self.rule_two = copy.deepcopy(self.rule_one)

    def test_equal(self):
        """Test where two rules are equal."""
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_equal_reversed_elements(self):
        """Test that source ranges are order independent."""
        self.rule_two['sourceRanges'] = [
            r for r in reversed(self.rule_two['sourceRanges'])
        ]

        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_equal_reversed_allowed_rules(self):
        """Test that allows in a rule are order independent."""
        self.rule_two[
            'allowed'] = [r for r in reversed(self.rule_two['allowed'])]

        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_equal_reversed_allowed_ports(self):
        """Test that ports in an allowed rules are order independent."""
        for allow in self.rule_two['allowed']:
            if 'ports' in allow:
                allow['ports'] = [r for r in reversed(allow['ports'])]

        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_network(self):
        """Test that inequal networks cause inequality."""
        self.rule_two['network'] = self.rule_two['network'].replace(
            'default', 'other')
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_source_ranges(self):
        """Test that inequal sourceRanges cause inequality."""
        self.rule_two['sourceRanges'].append('1.2.3.4/28')
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_allowed(self):
        """Test that inequal 'allowed' causes inequality."""
        self.rule_two['allowed'] = self.rule_two['allowed'][0:1]
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_descriptions(self):
        """Test that inequal descriptions cause inequality."""
        self.rule_two['description'] = 'Other Description.'
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_name(self):
        """Test that inequal name cause inequality."""
        self.rule_two['name'] = 'other-name'
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_source_tags(self):
        """Test that inequal sourceTags cause inequality."""
        self.rule_two['sourceTags'] = []
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)

    def test_inequal_target_tags(self):
        """Test that inequal targetTags cause inequality."""
        self.rule_two['targetTags'] = ['http-server']
        self.firewall_rules_1.add_rule(self.rule_one)
        self.firewall_rules_2.add_rule(self.rule_two)
        self.assertNotEqual(self.firewall_rules_1, self.firewall_rules_2)


if __name__ == '__main__':
    unittest.main()
