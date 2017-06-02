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

"""Tests for google.cloud.security.enforcer.gce_firewall_enforcer."""

import copy
import json
import threading
import mock

import testing_constants as constants
from tests.unittest_utils import ForsetiTestCase

from google.cloud.security.enforcer import gce_firewall_enforcer as fe


class HelperFunctionTest(ForsetiTestCase):
    """Unit tests for helper functions."""

    def test_get_network_name_from_url(self):
        """Verify that we can get the network name given a network url."""
        url = ('https://www.googleapis.com/compute/v1/projects/%s/global/'
               'networks/%s' % (constants.TEST_PROJECT, constants.TEST_NETWORK))
        self.assertEquals(constants.TEST_NETWORK,
                          fe.get_network_name_from_url(url))

    def test_build_network_url(self):
        """Verify that we can get a url from project and network name."""
        expected_url = ('https://www.googleapis.com/compute/v1/projects/'
                        '%s/global/networks/%s' %
                        (constants.TEST_PROJECT, constants.TEST_NETWORK))

        self.assertEqual(expected_url,
                         fe.build_network_url(constants.TEST_PROJECT,
                                              constants.TEST_NETWORK))


class ComputeFirewallAPITest(ForsetiTestCase):
    """Tests for the ComputeFirewallAPI class."""

    def setUp(self):
        """Set up."""
        self.gce_service = mock.MagicMock()
        self.firewall_api = fe.ComputeFirewallAPI(self.gce_service)

    def test_is_successful(self):
        """is_successful should know about bad responses and OK responses."""
        self.assertTrue(
            self.firewall_api.is_successful({
                'kind': 'compute#operation'
            }))
        self.assertFalse(
            self.firewall_api.is_successful({
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
            self.firewall_api.is_successful({
                'error': {
                    'errors': [{
                        'code': 'RESOURCE_ALREADY_EXISTS'
                    }]
                }
            }))

        self.assertTrue(
            self.firewall_api.is_successful({
                'error': {
                    'errors': [{
                        'code': 'INVALID_FIELD_VALUE'
                    }]
                }
            }))

    def test_wait_for_any_to_complete(self):
        """Testing waiting for requests until any finish executing.

        Setup:
          * Create mock pending response.
          * Create mock completed response.
          * Set compute.globalOperations.get to return mock completed response.

        Expected results:
          * wait_for_any_to_complete will return the completed and running
            responses
        """
        pending_responses = [{
            'name': 'operation-1400179586831',
            'status': 'PENDING'
        }, {
            'name': 'operation-1400179586832',
            'status': 'PENDING'
        }]

        completed_response = {
            'name': 'operation-1400179586831',
            'status': 'DONE'
        }
        running_response = {
            'name': 'operation-1400179586832',
            'status': 'PENDING'
        }

        self.gce_service.globalOperations().get().execute.side_effect = [
            completed_response, running_response
        ]

        (completed, running) = self.firewall_api.wait_for_any_to_complete(
            constants.TEST_PROJECT, pending_responses)

        self.assertEqual([completed_response], completed)
        self.assertEqual([running_response], running)

    def test_wait_for_any_to_complete_empty_responses_list(self):
        """Testing waiting for requests until any finish executing.

        Setup:
          * Run wait_for_any_to_complete with an empty list for pending
            responses.

        Expected results:
          * wait_for_any_to_complete will return an empty list for completed and
            running responses.
        """
        pending_responses = []

        (completed, running) = self.firewall_api.wait_for_any_to_complete(
            constants.TEST_PROJECT, pending_responses)
        self.assertEqual([], completed)
        self.assertEqual([], running)

    def test_wait_for_any_to_complete_timeout(self):
        """Testing waiting for requests until a timeout is exceeded.

        Setup:
          * Create mock pending response.
          * Set compute.globalOperations.get to return mock pending response.

        Expected results:
          * wait_for_any_to_complete will return the pending response with a
            timeout error
        """
        pending_response = {
            'name': 'operation-1400179586831',
            'status': 'PENDING'
        }

        expected_response = {
            'name': 'operation-1400179586831',
            'status': 'PENDING',
            'error': {
                'errors': [{
                    'code': 'OPERATION_TIMEOUT',
                    'message': 'Operation exceeded timeout for '
                               'completion of 1.00 seconds'
                }]
            }
        }

        self.gce_service.globalOperations().get().execute.return_value = (
            pending_response)

        (completed, running) = self.firewall_api.wait_for_any_to_complete(
            constants.TEST_PROJECT, [pending_response], timeout=1.0)
        self.assertEqual([expected_response], completed)
        self.assertEqual([], running)

    def test_wait_for_all_to_complete(self):
        """Testing waiting for requests until they all finish executing.

        Setup:
          * Create mock pending responses.
          * Create mock completed responses.
          * Set compute.globalOperations.get to return mock completed response.

        Expected results:
          * wait_for_all_to_complete will return the completed and running
            responses
        """
        pending_responses = [{
            'name': 'operation-1400179586831',
            'status': 'PENDING'
        }, {
            'name': 'operation-1400179586832',
            'status': 'PENDING'
        }]

        completed_responses = [{
            'name': 'operation-1400179586831',
            'status': 'DONE'
        }, {
            'name': 'operation-1400179586832',
            'status': 'DONE'
        }]

        self.gce_service.globalOperations().get().execute.side_effect = [
            completed_responses[0], pending_responses[1], completed_responses[1]
        ]

        completed = self.firewall_api.wait_for_all_to_complete(
            constants.TEST_PROJECT, pending_responses)
        self.assertEqual(completed_responses, completed)


class FirewallRulesTest(ForsetiTestCase):
    """Tests for the FirewallRules class."""

    def setUp(self):
        """Set up."""
        self.gce_service = mock.MagicMock()
        self.firewall_api = fe.ComputeFirewallAPI(self.gce_service)
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
        page_one = copy.deepcopy(constants.EXPECTED_FIREWALL_API_RESPONSE)
        page_one['items'] = page_one['items'][:1]
        page_one['nextPageToken'] = 'token'

        page_two = copy.deepcopy(constants.EXPECTED_FIREWALL_API_RESPONSE)
        page_two['items'] = page_two['items'][1:]

        self.gce_service.firewalls().list().execute.side_effect = [
            page_one, page_two
        ]

        self.firewall_rules.add_rules_from_api(self.firewall_api)

        self.assertSameStructure(constants.EXPECTED_FIREWALL_RULES,
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
        self.gce_service = mock.MagicMock()
        self.firewall_api = fe.ComputeFirewallAPI(self.gce_service)
        self.firewall_rules = fe.FirewallRules(constants.TEST_PROJECT)

        self.test_rule = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-1'])

    def test_valid(self):
        """Verify valid rules returns True."""
        self.assertTrue(
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

    def test_missing_source_key(self):
        """Rule missing source(Ranges|Tags) raises InvalidFirewallRuleError."""
        self.test_rule.pop('sourceRanges')
        with self.assertRaises(fe.InvalidFirewallRuleError):
            self.firewall_rules._check_rule_before_adding(self.test_rule)

        # Adding sourceTags makes the rule valid again
        self.test_rule['sourceTags'] = 'test-tag'
        self.assertTrue(
            self.firewall_rules._check_rule_before_adding(self.test_rule))

    def test_missing_ip_protocol(self):
        """Rule missing IPProtocol in an allow predicate raises an exception."""
        self.test_rule['allowed'][0].pop('IPProtocol')
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


class FirewallEnforcerTest(ForsetiTestCase):
    """Tests for the FirewallEnforcer class."""

    def setUp(self):
        """Set up.

        Creates a FirewallEnforcer object with current and expected rules set to
        an empty FirewallRules object.
        """
        self.gce_service = mock.MagicMock()
        self.firewall_api = fe.ComputeFirewallAPI(
            self.gce_service, dry_run=True)

        self.expected_rules = fe.FirewallRules(constants.TEST_PROJECT)
        self.current_rules = fe.FirewallRules(constants.TEST_PROJECT)

        self.project_sema = threading.BoundedSemaphore(value=1)
        self.operation_sema = threading.BoundedSemaphore(value=5)

        self.enforcer = fe.FirewallEnforcer(
            constants.TEST_PROJECT, self.firewall_api, self.expected_rules,
            self.current_rules, self.project_sema, self.operation_sema)

    def test_apply_firewall_no_changes(self):
        """No changes when current and expected rules match."""
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES
        self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES

        changed_count = self.enforcer.apply_firewall()
        self.assertEqual(0, changed_count)

    def test_apply_firewall_no_rules(self):
        """Raises exception if no expected_rules defined."""
        with self.assertRaises(fe.FirewallEnforcementFailedError):
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

        self.gce_service.firewalls().list().execute.return_value = (
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

        # Rule three isn't part of EXPECTED_FIREWALL_RULES.  It should be removed.
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
            'network': (u'https://www.googleapis.com/compute/v1/projects/'
                        'test-project/global/networks/test-network'),
            'sourceRanges': [u'10.2.3.4/32'],
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
        for rule in [
                'test-network-allow-internal-1', 'test-network-allow-public-0'
        ]:
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
        for rule in [
                'test-network-allow-internal-1', 'test-network-allow-public-0'
        ]:
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

        self.assertSameStructure(self.enforcer.get_updated_rules(
        ), [constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0']])

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
            'network': (u'https://www.googleapis.com/compute/v1/projects/'
                        'google.com:secops-testing/global/networks/test-net'),
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

        with self.assertRaises(fe.FirewallEnforcementFailedError):
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
        with self.assertRaises(fe.FirewallEnforcementFailedError):
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
        delete_function = self.firewall_api.delete_firewall_rule
        insert_function = self.firewall_api.insert_firewall_rule
        update_function = self.firewall_api.update_firewall_rule

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
        delete_function = self.firewall_api.delete_firewall_rule
        (successes, failures, change_errors) = self.enforcer._apply_change(
            delete_function, [])
        self.assertListEqual([], successes)
        self.assertListEqual([], failures)
        self.assertListEqual([], change_errors)

    def test_apply_change_insert_http_error(self):
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
        error_409 = fe.errors.HttpError(response, '', '')

        insert_function = mock.Mock(side_effect=error_409)

        test_rules = [
            copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[
                'test-network-allow-internal-0'])
        ]

        (successes, failures, change_errors) = self.enforcer._apply_change(
            insert_function, test_rules)
        self.assertSameStructure(test_rules, failures)
        self.assertListEqual([], successes)
        error_str = 'Rule: %s\nError: %s' % (test_rules[0], error_409)
        self.assertListEqual([error_str], change_errors)

    def test_apply_change_operation_status_error(self):
        """Adds the rule to failures on HttpError exception.

        Setup:
          * Create a mock _create_dry_run_response method.
          * Set _create_dry_run_response to return an error response for all
            operations.
          * Run apply_change.

        Expected Results:
          * Passed in rule ends up in failures list.
        """
        insert_function = self.firewall_api.insert_firewall_rule
        self.firewall_api._create_dry_run_response = mock.Mock()
        self.firewall_api._create_dry_run_response.return_value = {
            'error': {
                'errors': [{
                    'code': 'NOT_FOUND'
                }]
            },
            'status': 'DONE',
            'name': 'test'
        }

        test_rules = [
            copy.deepcopy(constants.EXPECTED_FIREWALL_RULES[
                'test-network-allow-internal-0'])
        ]

        (successes, failures, change_errors) = self.enforcer._apply_change(
            insert_function, test_rules)
        self.assertSameStructure(test_rules, failures)
        self.assertListEqual([], successes)
        self.assertListEqual([], change_errors)

    def test_apply_change_lots_of_rules(self):
        """Changing more rules than permitted by the operation semaphore works.

        Setup:
          * Create a new bounded semaphore with a limit of 2 operations.
          * Create a list of 10 rules to insert.
          * Run _apply_change.

        Expected Results:
          * All rules end up in the successes list.
        """
        insert_function = self.firewall_api.insert_firewall_rule
        self.enforcer.operation_sema = threading.BoundedSemaphore(value=2)

        test_rule_name = 'test-network-allow-internal-0'
        test_rule = constants.EXPECTED_FIREWALL_RULES[test_rule_name]

        test_rules = []
        for i in xrange(10):
            rule = copy.deepcopy(test_rule)
            rule['name'] = '%s-%i' % (test_rule_name, i)
            test_rules.append(rule)

        (successes, failures, change_errors) = self.enforcer._apply_change(
            insert_function, test_rules)
        self.assertSameStructure(test_rules, successes)
        self.assertListEqual([], failures)
        self.assertListEqual([], change_errors)

    def test_apply_changes(self):
        """Validate _apply_changes works with no errors.

        Setup:
          * Set current and expected rules to EXPECTED_FIREWALL_RULES.
          * Add one rule each to rules_to_(delete|insert|update).
          * Run _apply_change_set.

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

        changed_count = self.enforcer._apply_change_set()

        self.assertEqual(3, changed_count)

        self.assertSameStructure([
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-1']
        ], self.enforcer.get_deleted_rules())

        self.assertSameStructure([
            constants.EXPECTED_FIREWALL_RULES['test-network-allow-internal-0']
        ], self.enforcer.get_inserted_rules())

        self.assertSameStructure(
            [constants.EXPECTED_FIREWALL_RULES['test-network-allow-public-0']],
            self.enforcer.get_updated_rules())

    def test_apply_changes_operation_status_error(self):
        """Validate that an error on a change raises the expected exception.

        Setup:
          * Set current and expected rules to EXPECTED_FIREWALL_RULES.
          * Create a mock _create_dry_run_response method.
          * Set _create_dry_run_response to return an error response for all
            operations.
          * Run _apply_changes three times, once to delete, once to insert and
            once to update.

        Expected Results:
          * Each time it is run, _apply_changes should raise a
            FirewallEnforcementFailedError exception.
          * get_(deleted|inserted|updated)_rules() should return an empty list.
        """
        self.current_rules.rules = constants.EXPECTED_FIREWALL_RULES
        self.expected_rules.rules = constants.EXPECTED_FIREWALL_RULES

        self.firewall_api._create_dry_run_response = mock.Mock()
        self.firewall_api._create_dry_run_response.return_value = {
            'error': {
                'errors': [{
                    'code': 'NOT_FOUND'
                }]
            },
            'status': 'DONE',
            'name': 'test'
        }

        self.enforcer._rules_to_delete = ['test-network-allow-internal-0']
        with self.assertRaises(fe.FirewallEnforcementFailedError):
            self.enforcer._apply_change_set()
        self.assertEqual([], self.enforcer.get_deleted_rules())
        self.enforcer._rules_to_delete = []

        self.enforcer._rules_to_insert = ['test-network-allow-internal-0']
        with self.assertRaises(fe.FirewallEnforcementFailedError):
            self.enforcer._apply_change_set()
        self.assertEqual([], self.enforcer.get_inserted_rules())
        self.enforcer._rules_to_insert = []

        self.enforcer._rules_to_update = ['test-network-allow-internal-0']
        with self.assertRaises(fe.FirewallEnforcementFailedError):
            self.enforcer._apply_change_set()
        self.assertEqual([], self.enforcer.get_updated_rules())
        self.enforcer._rules_to_update = []


class FirewallRulesAreEqualTest(ForsetiTestCase):
    """Multiple tests for (in)equality between two firewall rules."""

    def setUp(self):
        """Start with two identical rules."""
        self.firewall_rules_1 = fe.FirewallRules(constants.TEST_PROJECT)
        self.firewall_rules_2 = fe.FirewallRules(constants.TEST_PROJECT)

        self.rule_one = {
            'network': ('https://www.googleapis.com/compute/v1/'
                        'projects/test-project/global/'
                        'networks/test-network'),
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
            'test-network', 'other')
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
