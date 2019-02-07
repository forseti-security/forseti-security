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

"""Tests for google.cloud.forseti.enforcer.project_enforcer."""

import copy
from datetime import datetime
import json
import unittest
from googleapiclient import errors
import httplib2
import mock

from tests.enforcer import testing_constants as constants

from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import repository_mixins
from google.cloud.forseti.enforcer import enforcer_log_pb2
from google.cloud.forseti.enforcer import project_enforcer


class ProjectEnforcerTest(constants.EnforcerTestCase):
    """Extended unit tests for ProjectEnforcer class."""

    def setUp(self):
        """Set up."""
        super(ProjectEnforcerTest, self).setUp()
        self.enforcer = project_enforcer.ProjectEnforcer(
            self.project, compute_client=self.gce_api_client, dry_run=True)

        self.expected_proto = enforcer_log_pb2.ProjectResult(
            timestamp_sec=constants.MOCK_MICROTIMESTAMP,
            project_id=self.project)

        self.expected_rules = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES.values())

        response_403 = httplib2.Response({
            'status': '403',
            'content-type': 'application/json'
        })
        response_403.reason = 'Failed'
        self.error_403 = errors.HttpError(response_403, '', uri='')

        self.addCleanup(mock.patch.stopall)

    def set_expected_audit_log(self,
                               added=None,
                               deleted=None,
                               updated=None,
                               unchanged=None):
        """Adds the GceFirewallEnforcementResult proto to the expected_proto."""
        results = self.expected_proto.gce_firewall_enforcement
        results.rules_modified_count = 0
        if added:
            results.rules_added.extend(added)
            results.rules_modified_count += len(added)

        if deleted:
            results.rules_removed.extend(deleted)
            results.rules_modified_count += len(deleted)

        if updated:
            results.rules_updated.extend(updated)
            results.rules_modified_count += len(updated)

        if unchanged:
            results.rules_unchanged.extend(unchanged)

    def validate_results(self, expected_proto, actual_proto,
                         expect_rules_before=False, expect_rules_after=False):
        """Check that the expected proto matches the actual proto.

        Removes the rules_before and rules_after messages from the actual_proto
        before comparing.

        Args:
            expected_proto: The expected response.
            actual_proto: The actual responses.
            expect_rules_before: If actual response should contain a
                rules_before message.
            expect_rules_after: If actual response should contain a
                rules_after message.
        """
        if expect_rules_before:
            self.assertTrue(
                actual_proto.gce_firewall_enforcement.HasField('rules_before'))
            actual_proto.gce_firewall_enforcement.ClearField('rules_before')
        if expect_rules_after:
            self.assertTrue(
                actual_proto.gce_firewall_enforcement.HasField('rules_after'))
            actual_proto.gce_firewall_enforcement.ClearField('rules_after')
        self.assertEqual(expected_proto, actual_proto)

    def test_enforce_policy_no_changes(self):
        """Validate results when there are no firewall policies changed.

        Setup:
          * Set API calls to return the same networks and firewall rules listed
            in the RAW_EXPECTED_JSON_POLICY.

        Expected Results:
          A ProjectResult proto with status=SUCCESS and all rules listed in
          rules_unchanged.
        """
        self.gce_api_client.get_firewall_rules.return_value = (
            self.expected_rules)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        unchanged = get_rule_names(self.expected_rules)
        self.set_expected_audit_log(unchanged=unchanged)

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.validate_results(self.expected_proto, result)

    def test_enforce_policy_all_rules_changed(self):
        """Validate results when all firewall policies are changed.

        Setup:
          * Set API calls to return the different firewall rules from the new
            policy on the first call, and the expected new firewall rules on the
            second call.

        Expected Results:
          A ProjectResult proto showing status=SUCCESS, details on the rules
          changed, all_rules_changed set to True, and a copy of the previous and
          current firewall rules.
        """
        self.gce_api_client.get_firewall_rules.side_effect = [
            constants.DEFAULT_FIREWALL_API_RESPONSE,
            self.expected_rules,
        ]

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        self.expected_proto.gce_firewall_enforcement.all_rules_changed = True

        added = get_rule_names(self.expected_rules)
        deleted = get_rule_names(
            constants.DEFAULT_FIREWALL_API_RESPONSE)
        self.set_expected_audit_log(added=added, deleted=deleted)

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    def test_enforce_policy_multiple_rules_changed(self):
        """Validate results when multiple firewall policies are changed.

        Setup:
          * Create a new set of rules that is a copy of the expected rules.
            - Delete last rule so it will have to be re-added.
            - Modify the first rule so it will have to be updated.
            - Add a new rule from a different policy so it will have to be
              deleted.

          * Set API call to return the current firewall rules on the first call,
            and the expected new firewall rules on the second call.

        Expected Results:
          A ProjectResult proto showing status=SUCCESS, details on the rules
          changed, and a copy of the previous and current firewall rules.
        """
        # Make a deep copy of the expected rules
        current_fw_rules = copy.deepcopy(self.expected_rules)

        # Delete the last rule, so it has to be re-added
        current_fw_rules.pop()

        # Make a change to the first rule so it has to be updated
        current_fw_rules[0]['sourceRanges'].append('10.0.0.0/8')

        # Add a new rule that will need to be deleted
        current_fw_rules.append(
            constants.DEFAULT_FIREWALL_API_RESPONSE[0])

        self.gce_api_client.get_firewall_rules.side_effect = [
            current_fw_rules,
            self.expected_rules,
        ]

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        added = get_rule_names(self.expected_rules[-1:])  # Expected rule added
        deleted = get_rule_names(current_fw_rules[-1:])  # Current rule deleted
        updated = get_rule_names(current_fw_rules[:1])  # First rule updated
        unchanged = get_rule_names(current_fw_rules[1:2])  # Others unchanged
        self.set_expected_audit_log(added, deleted, updated, unchanged)

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    def test_enforce_policy_one_rule_updated(self):
        """Validate results when a firewall rule is changed.

        Setup:
          * Set API calls to return the different firewall rules from the new
            policy on the first call, and the expected new firewall rules on the
            second call.

        Expected Results:
          A ProjectResult proto showing status=SUCCESS, details on the rules
          changed, and a copy of the previous and current firewall rules.
        """
        # Make a deep copy of the expected rules
        current_fw_rules = copy.deepcopy(self.expected_rules)

        # Make a change to one of the rules
        current_fw_rules[0]['sourceRanges'].append('10.0.0.0/8')

        self.gce_api_client.get_firewall_rules.side_effect = [
            current_fw_rules,
            self.expected_rules,
        ]

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        updated = get_rule_names(current_fw_rules[:1])  # First rule updated
        unchanged = get_rule_names(current_fw_rules[1:])  # Others unchanged
        self.set_expected_audit_log(updated=updated, unchanged=unchanged)

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    def test_enforce_policy_all_rules_changed_with_retry(self):
        """Validate results when a rule is added while the enforcer is running.

        Setup:
          * Set API calls to return the different firewall rules from the new
            policy on the first call, the expected rules with an additional rule
            added on the second and third calls, and the expected new firewall
            rules on the forth call.
          * Set retry_on_dry_run to True so that code path will be tested.

        Expected Results:
          A ProjectResult proto showing status=SUCCESS, details on the rules
          changed, all_rules_changed set to True, and a copy of the previous and
          current firewall rules.
        """
        extra_rules = copy.deepcopy(self.expected_rules)
        extra_rules.extend(
            constants.DEFAULT_FIREWALL_API_RESPONSE[:1])
        self.gce_api_client.get_firewall_rules.side_effect = [
            constants.DEFAULT_FIREWALL_API_RESPONSE,
            extra_rules,
            extra_rules,
            self.expected_rules
        ]

        result = self.enforcer.enforce_firewall_policy(
            self.policy, retry_on_dry_run=True)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        self.expected_proto.gce_firewall_enforcement.all_rules_changed = True

        added = get_rule_names(self.expected_rules)
        deleted = get_rule_names(
            constants.DEFAULT_FIREWALL_API_RESPONSE)
        deleted.extend(get_rule_names(
            constants.DEFAULT_FIREWALL_API_RESPONSE[:1]))

        self.set_expected_audit_log(added=added, deleted=sorted(deleted))

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    def test_enforce_policy_rules_changed_exceeds_maximum_retries(self):
        """Validate error status if rule is constantly readded while enforcing.

        Setup:
          * Set API calls to return the different firewall rules from the new
            policy on the first call, the expected rules with an additional rule
            added on all subsequent calls.
          * Set retry_on_dry_run to True so that code path will be tested.

        Expected Results:
          A ProjectResult proto showing status=ERROR, details on the rules
          changed, and a copy of the previous and current firewall rules.
        """
        extra_rules = copy.deepcopy(self.expected_rules)
        extra_rules.extend(
            constants.DEFAULT_FIREWALL_API_RESPONSE[:1])

        firewall_list = [
            constants.DEFAULT_FIREWALL_API_RESPONSE,
            extra_rules
        ]

        maximum_retries = 3

        # Return the same extra rule for each retry.
        firewall_list.extend([extra_rules] * maximum_retries * 2)

        self.gce_api_client.get_firewall_rules.side_effect = firewall_list

        result = self.enforcer.enforce_firewall_policy(
            self.policy, retry_on_dry_run=True, maximum_retries=maximum_retries)

        self.expected_proto.status = project_enforcer.STATUS_ERROR
        self.expected_proto.status_reason = (
            'New firewall rules do not match the expected rules enforced by '
            'the policy')

        added = get_rule_names(self.expected_rules)
        deleted = get_rule_names(
            constants.DEFAULT_FIREWALL_API_RESPONSE)

        # Rule is deleted 3 times, but always comes back.
        for _ in range(maximum_retries):
            deleted.extend(get_rule_names(
                constants.DEFAULT_FIREWALL_API_RESPONSE[:1]))

        unchanged = get_rule_names(
            constants.DEFAULT_FIREWALL_API_RESPONSE[:1])

        self.set_expected_audit_log(added=added, deleted=sorted(deleted),
                                    unchanged=unchanged)

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    def test_enforce_policy_rules_changed_no_retry_if_skipped(self):
        """Retry is not attempted when prechange callback returns false.

        Setup:
          * Set API calls to return the different firewall rules from the new
            policy on all calls.
          * Set retry_on_dry_run arg to True so that code path will be tested.
          * Set prechange_callback arg to a function that always returns false.

        Expected Results:
          A ProjectResult proto showing status=SUCCESS, with no rules changed.
        """
        self.gce_api_client.get_firewall_rules.return_value = (
            constants.DEFAULT_FIREWALL_API_RESPONSE)

        prechange_callback_func = lambda *unused_args: False

        result = self.enforcer.enforce_firewall_policy(
            self.policy, prechange_callback=prechange_callback_func,
            retry_on_dry_run=True)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS

        unchanged = get_rule_names(constants.DEFAULT_FIREWALL_API_RESPONSE)

        self.set_expected_audit_log(added=[], deleted=[], unchanged=unchanged)

        self.validate_results(self.expected_proto, result)

    def test_enforce_policy_one_network(self):
        """Validate that running on a single network only changes that network.

        Setup:
          * Set API calls to return default rules on two networks for the first
            call and the expected rules on the test network for the second
            call.

        Expected Results:
          The rules on the test network are changed, but the rules on the
          default network remain the same.
        """
        current_fw_rules_network1 = copy.deepcopy(
            constants.DEFAULT_FIREWALL_API_RESPONSE)
        current_fw_rules_network2 = json.loads(
            json.dumps(constants.DEFAULT_FIREWALL_API_RESPONSE).replace(
                'test-network', 'default'))

        expected_fw_rules_network1 = copy.deepcopy(
            constants.EXPECTED_FIREWALL_API_RESPONSE)
        expected_fw_rules_network2 = copy.deepcopy(current_fw_rules_network2)

        self.gce_api_client.get_firewall_rules.side_effect = [
            current_fw_rules_network1 + current_fw_rules_network2,
            expected_fw_rules_network1 + expected_fw_rules_network2
        ]

        result = self.enforcer.enforce_firewall_policy(
            self.policy, networks=[constants.TEST_NETWORK])

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        added = get_rule_names(expected_fw_rules_network1)
        deleted = get_rule_names(current_fw_rules_network1)
        unchanged = get_rule_names(current_fw_rules_network2)
        self.set_expected_audit_log(
            added=added, deleted=deleted, unchanged=unchanged)

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    def test_project_enforcer_empty_firewall_policy_exception(self):
        """Verifies that an empty firewall policy raises exception.

        Setup:
          * Set the firewall policy to an empty list.
          * Set the current firewall rules.
          * Enforce the expected policy which will raise an exception.

        Expected Result:
          A ProjectResult proto showing status=ERROR and a reason string.
        """
        firewall_policy = []

        self.gce_api_client.get_firewall_rules.return_value = (
                self.expected_rules)

        result = self.enforcer.enforce_firewall_policy(firewall_policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR
        self.expected_proto.status_reason = (
            'error enforcing firewall for project: No rules defined in the '
            'expected rules.')
        unchanged = get_rule_names(self.expected_rules)
        self.set_expected_audit_log(unchanged=unchanged)

        self.validate_results(self.expected_proto, result)

    def test_project_enforcer_empty_firewall_policy_allowed(self):
        """Verifies that an empty firewall policy deletes all rules if allowed.

        Setup:
          * Set the firewall policy to an empty list.
          * Set the current firewall rules.
          * Set allow_empty_ruleset to True.
          * Enforce the expected policy which deletes all rules.

        Expected Result:
          A ProjectResult proto showing status=SUCCESS and the number of rules
          changed in an audit_log, and a copy of the previous and current
          firewall rules.
        """
        firewall_policy = []

        self.gce_api_client.get_firewall_rules.side_effect = [
            self.expected_rules,
            []
        ]

        result = self.enforcer.enforce_firewall_policy(
            firewall_policy, allow_empty_ruleset=True)

        self.expected_proto.status = project_enforcer.STATUS_SUCCESS
        self.expected_proto.gce_firewall_enforcement.all_rules_changed = True
        deleted = get_rule_names(self.expected_rules)
        self.set_expected_audit_log(deleted=deleted)

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)

    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    def test_enforce_policy_firewall_enforcer_error(self, mock_logger):
        """Verifies that a firewall enforcer error returns a status=ERROR proto.

        Setup:
          * Switch the dry run response to a firewall change to be an error.
          * Set the current firewall rules to something different from the
            policy.
          * Enforce the expected policy which will force a firewall change.

        Expected Result:
          A ProjectResult proto showing status=ERROR and a reason string.
        """
        # Make a deep copy of the expected rules
        current_fw_rules = copy.deepcopy(self.expected_rules)

        # Make a change to one of the rules
        current_fw_rules[0]['sourceRanges'].append('10.0.0.0/8')

        self.gce_api_client.get_firewall_rules.return_value = current_fw_rules

        with mock.patch.object(
                repository_mixins, '_create_fake_operation') as mock_dry_run:

            mock_dry_run.return_value = {
                'status': 'DONE',
                'name': 'test-net-allow-all-tcp',
                'error': {
                    'errors': [{
                        'code': 'ERROR'
                    }]
                }
            }
            result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR
        unchanged = get_rule_names(self.expected_rules)
        self.set_expected_audit_log(unchanged=unchanged)

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'error enforcing firewall for project')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result)
        self.assertTrue(mock_logger.error.called)

    @mock.patch('google.cloud.forseti.enforcer.gce_firewall_enforcer.LOGGER', autospec=True)
    def test_enforce_policy_failure_during_enforcement(self, mock_logger):
        """Forces an error in the middle of enforcing a policy.

        Setup:
          * Create a new set of rules that is a copy of the expected rules.
            - Delete last rule so it will have to be re-added.
            - Modify the first rule so it will have to be updated.
            - Add a new rule from a different policy so it will have to be
              deleted.

          * Mock the update function so it returns an error. Updates are always
            done after inserts and deletes.

          * Set API call to return the current firewall rules on the first call,
            and the partially updated firewall rules on the second call.

        Expected Results:
          A ProjectResult proto showing status=ERROR, the correct reason string,
          the number of rules changed in an audit_log, and a copy of the
          previous and current firewall rules.
        """
        # Make a change to the first rule so it should be updated. The update
        # will fail so this rule will still not match the policy.
        self.expected_rules[0]['sourceRanges'].append('10.0.0.0/8')

        # Start with the rules as they exist after enforce_firewall_policy is
        # run and modify them.
        current_fw_rules = copy.deepcopy(self.expected_rules)

        # Delete the last rule, so it has to be re-added
        current_fw_rules.pop()

        # Add a new rule that will need to be deleted
        current_fw_rules.append(
            constants.DEFAULT_FIREWALL_API_RESPONSE[0])

        self.gce_api_client.get_firewall_rules.side_effect = [
            current_fw_rules,
            self.expected_rules,
        ]

        with mock.patch.object(self.gce_api_client,
                               'patch_firewall_rule') as mock_updater:
            mock_updater.return_value = {
                'status': 'DONE',
                'name': 'test-net-allow-corp-internal-0',
                'error': {
                    'errors': [{
                        'code': 'ERROR'
                    }]
                }
            }

            result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR
        added = get_rule_names(self.expected_rules[-1:])  # expected rule added
        deleted = get_rule_names(current_fw_rules[-1:])  # current rule deleted
        unchanged = get_rule_names(current_fw_rules[0:2])  # others unchanged
        self.set_expected_audit_log(
            added=added, deleted=deleted, unchanged=unchanged)

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'error enforcing firewall for project')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True, expect_rules_after=True)
        self.assertTrue(mock_logger.error.called)

    @mock.patch('google.cloud.forseti.enforcer.project_enforcer.LOGGER', autospec=True)
    def test_enforce_policy_error_fetching_updated_rules(self, mock_logger):
        """Forces an error when requesting firewall rules after enforcement.

        Setup:
          * Create a new set of rules that is a copy of the expected rules.
            - Modify the first rule so it will have to be updated.

          * Set API call to return the current firewall rules on the first call,
            and an error on the second call.

        Expected Results:
          A ProjectResult proto showing status=ERROR, the correct reason string,
          the number of rules changed in an audit_log, and a copy of the
          previous firewall rules only.
        """
        # Make a deep copy of the expected rules
        current_fw_rules = copy.deepcopy(self.expected_rules)

        # Make a change to one of the rules
        current_fw_rules[0]['sourceRanges'].append('10.0.0.0/8')

        err = api_errors.ApiExecutionError(self.project, self.error_403)

        self.gce_api_client.get_firewall_rules.side_effect = [
            current_fw_rules,
            err,
            err,
        ]


        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR
        updated = get_rule_names(current_fw_rules[:1])  # First rule updated
        self.set_expected_audit_log(updated=updated)

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'error getting current firewall rules from API:')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        # Verify rules after json is an empty string
        self.assertEqual(
            self.expected_proto.gce_firewall_enforcement.rules_after.json, '')

        self.validate_results(self.expected_proto, result,
                              expect_rules_before=True,
                              expect_rules_after=False)
        self.assertTrue(mock_logger.error.called)

    @mock.patch('google.cloud.forseti.enforcer.project_enforcer.LOGGER', autospec=True)
    def test_enforce_policy_error_listing_networks(self, mock_logger):
        """Forces an error when listing project networks.

        Setup:
          * Set the networks.list API call to return an error.
          * Set the firewalls.list API call to return the current firewall
            rules.

        Expected Results:
          A ProjectResult proto showing status=ERROR and the correct reason
          string.
        """
        err = api_errors.ApiExecutionError(self.project, self.error_403)
        self.gce_api_client.get_networks.side_effect = err

        self.gce_api_client.get_firewall_rules.return_value = (
                self.expected_rules)

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR
        self.expected_proto.status_reason = (
                'error getting current networks from API: <HttpError 403 '
                '"Failed">')

        self.validate_results(self.expected_proto, result)
        self.assertTrue(mock_logger.exception.called)

    def test_enforce_policy_error_listing_firewalls(self):
        """Forces an error when listing project firewall rules.

        Setup:
          * Set the firewalls.list API call to return an error.

        Expected Results:
          A ProjectResult proto showing status=ERROR and the correct reason
          string.
        """
        err = api_errors.ApiExecutionError(self.project, self.error_403)
        self.gce_api_client.get_firewall_rules.side_effect = err

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'error getting current firewall rules from API:')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result)

    def test_enforce_policy_error_adding_rules(self):
        """Forces an error when adding the expected firewall policy rules.

        Setup:
          * Set the first firewall policy rule to have a very long name.

        Expected Results:
          A ProjectResult proto showing status=ERROR and the correct reason
          string.
        """
        # Set the first firewall policy rule to have a very long name
        self.policy[0]['name'] = 'long-name-' + 'x' * 54

        self.gce_api_client.get_firewall_rules.return_value = (
            self.expected_rules)

        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_ERROR

        # Match first part of error reason string
        self.assertStartsWith(
            result.status_reason,
            'error adding the expected firewall rules from the '
            'policy:')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result)

    def test_enforce_policy_firewall_enforcer_deleted_403(self):
        """Verifies that a deleted project returns status=PROJECT_DELETED.

        Setup:
          * Switch the list_firewalls response to be a 403 error with the reason
            string set to pending deletion.

        Expected Result:
          A ProjectResult proto showing status=PROJECT_DELETED and the correct
          reason string.
        """
        deleted_403 = httplib2.Response({
            'status': '403',
            'content-type': 'application/json'
        })
        deleted_403.reason = ('Project has been scheduled for deletion and '
                              'cannot be used for API calls. Visit '
                              'https://console.developers.google.com/iam-admin/'
                              'projects?pendingDeletion=true to undelete the '
                              'project.')
        error_deleted_403 = errors.HttpError(deleted_403, '', uri='')
        err = api_errors.ApiExecutionError(self.project, error_deleted_403)

        self.gce_api_client.get_networks.side_effect = err
        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_DELETED

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'Project scheduled for deletion')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result)

    def test_enforce_policy_firewall_enforcer_deleted_400(self):
        """Verifies that a deleted project returns a status=PROJECT_DELETED.

        Setup:
          * Switch the ListFirewalls response to be a 400 error with the reason
            string set to unknown project.

        Expected Result:
          A ProjectResult proto showing status=PROJECT_DELETED and the correct
          reason string.
        """
        deleted_400 = httplib2.Response({
            'status': '400',
            'content-type': 'application/json'
        })
        deleted_400.reason = 'Invalid value for project: %s' % self.project
        error_deleted_400 = errors.HttpError(deleted_400, '', uri='')
        err = api_errors.ApiExecutionError(self.project, error_deleted_400)

        self.gce_api_client.get_firewall_rules.side_effect = err
        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_DELETED

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'Project scheduled for deletion')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result)

    @mock.patch('google.cloud.forseti.enforcer.project_enforcer.LOGGER', autospec=True)
    def test_enforce_policy_firewall_enforcer_gce_api_disabled(self, mock_logger):
        """Project returns a status=PROJECT_DELETED if GCE API is disabled.

        Setup:
          * Switch the ListFirewalls response to be a 403 error with the reason
            string set to GCE API disabled.

        Expected Result:
          A ProjectResult proto showing status=PROJECT_DELETED and the correct
          reason string.
        """
        api_disabled_403 = httplib2.Response(
            {'status': '403',
             'content-type': 'application/json'})
        api_disabled_403.reason = (
            'Access Not Configured. Compute Engine API has not been used in '
            'project 1 before or it is disabled. Enable it by visiting '
            'https://console.developers.google.com/apis/api/compute_component/'
            'overview?project=1 then retry. If you enabled this API recently,'
            'wait a few minutes for the action to propagate to our systems and '
            'retry.')
        error_api_disabled_403 = errors.HttpError(api_disabled_403, '', uri='')
        err = api_errors.ApiNotEnabledError(
            'https://console.developers.google.com/apis/api/compute_component/',
            error_api_disabled_403)

        self.gce_api_client.get_firewall_rules.side_effect = err
        result = self.enforcer.enforce_firewall_policy(self.policy)

        self.expected_proto.status = project_enforcer.STATUS_DELETED

        # Match first part of error reason string
        self.assertStartsWith(result.status_reason,
                              'Project has GCE API disabled')

        # Copy reason string into expected proto. The reason includes a long
        # error message, which would be ugly to replicate in the test.
        self.expected_proto.status_reason = result.status_reason

        self.validate_results(self.expected_proto, result)
        self.assertTrue(mock_logger.error.called)


def get_rule_names(rules):
    """Returns a sorted list of rule names from the rules list."""
    return sorted([r['name'] for r in rules])


if __name__ == '__main__':
    unittest.main()
