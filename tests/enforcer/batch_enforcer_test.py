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

"""Tests for google.cloud.forseti.enforcer.batch_enforcer."""

import copy
from datetime import datetime
import unittest
import mock

from tests.enforcer import testing_constants as constants
from google.protobuf import text_format

from google.cloud.forseti.enforcer import enforcer_log_pb2
from google.cloud.forseti.enforcer import batch_enforcer


class BatchFirewallEnforcerTest(constants.EnforcerTestCase):
    """Extended unit tests for BatchFirewallEnforcer class."""

    def setUp(self):
        """Set up."""
        super(BatchFirewallEnforcerTest, self).setUp()
        self.batch_enforcer = batch_enforcer.BatchFirewallEnforcer(
            dry_run=True)
        self.batch_enforcer._local = mock.Mock(
            compute_client=self.gce_api_client)

        self.expected_summary = (
            enforcer_log_pb2.BatchResult(
                batch_id=constants.MOCK_MICROTIMESTAMP,
                timestamp_start_msec=constants.MOCK_MICROTIMESTAMP,
                timestamp_end_msec=constants.MOCK_MICROTIMESTAMP))

        self.expected_rules = copy.deepcopy(
            constants.EXPECTED_FIREWALL_RULES.values())

        self.addCleanup(mock.patch.stopall)

    def test_batch_enforcer_run_no_changes(self):
        """Validate a full pass of BatchFirewallEnforcer for a single project.

        Setup:
          * Set the mock API to return the correct results for the project.
          * Send a mock project and policy to run().

        Expected results:
          An EnforcerLog proto showing 1 success.
        """
        self.gce_api_client.get_firewall_rules.return_value = (
            constants.EXPECTED_FIREWALL_API_RESPONSE)

        project_policies = [(self.project, self.policy)]
        results = self.batch_enforcer.run(project_policies)

        self.expected_summary.projects_total = 1
        self.expected_summary.projects_success = 1
        self.expected_summary.projects_unchanged = 1

        self.assertEqual(self.expected_summary, results.summary)

        # Verify additional fields added to ProjectResults proto
        self.assertEqual(constants.MOCK_MICROTIMESTAMP,
                         results.results[0].batch_id)

    def test_batch_enforcer_run_all_changed(self):
        """Validate a full pass of BatchFirewallEnforcer for a single project.

        Setup:
          * Set API calls to return the different firewall rules from the new
            policy on the first call, and the expected new firewall rules on the
            second call.
          * Send a mock project and policy to run().

        Expected results:
          An EnforcerLog proto showing 1 success, 1 project changed, and 1
          projects with all_rules_changed.
        """
        self.gce_api_client.get_firewall_rules.side_effect = [
            constants.DEFAULT_FIREWALL_API_RESPONSE,
            constants.EXPECTED_FIREWALL_API_RESPONSE]

        project_policies = [(self.project, self.policy)]
        results = self.batch_enforcer.run(project_policies)

        self.expected_summary.projects_total = 1
        self.expected_summary.projects_success = 1
        self.expected_summary.projects_changed = 1
        self.expected_summary.projects_unchanged = 0

        self.assertEqual(self.expected_summary, results.summary)

    def test_batch_enforcer_run_prechange_callback(self):
        """Prechange callback that returns False stops changes from being made.

        Setup:
          * Set API calls to return a firewall rule that doesn't match the
            expected policy.
          * Create a prechange callback function that always returns False.
          * Send a mock project and policy to run().

        Expected results:
          An EnforcerLog proto showing 1 success, 1 project unchanged.
        """
        self.gce_api_client.get_firewall_rules.return_value = (
            constants.DEFAULT_FIREWALL_API_RESPONSE)

        project_policies = [(self.project, self.policy)]

        # Use a mutable list to get around nonlocal variable restrictions
        callback_called = [0]
        def prechange_callback(project, rules_to_delete, rules_to_insert,
                               rules_to_update):
            self.assertEqual(self.project, project)
            self.assertEqual(sorted(constants.DEFAULT_FIREWALL_RULES),
                             sorted(rules_to_delete))
            self.assertEqual(sorted(constants.EXPECTED_FIREWALL_RULES),
                             sorted(rules_to_insert))
            self.assertEqual([], rules_to_update)
            callback_called[0] += 1
            return False

        results = self.batch_enforcer.run(project_policies,
                                          prechange_callback=prechange_callback)

        self.expected_summary.projects_total = 1
        self.expected_summary.projects_success = 1
        self.expected_summary.projects_unchanged = 1

        self.assertEqual(self.expected_summary, results.summary)

        self.assertEqual(1, callback_called[0])

    def test_batch_enforcer_run_result_callback(self):
        """Validates that a callback function is called with for each result.

        Setup:
          * Create a callback function that asserts the value of the result is
            correct and counts the number of times it is called.
          * Set API calls to return the different firewall rules from the new
            policy on the first call, and the expected new firewall rules on the
            second call.
          * Send a mock project and policy to run().

        Expected Results:
          The callback function is called once with the correct result proto.
        """
        # Use a mutable list to get around nonlocal variable restrictions
        callback_called = [0]

        def result_callback(result):
            expected_result = enforcer_log_pb2.ProjectResult()
            text_format.Merge(constants.SAMPLE_ENFORCER_PROJECTRESULTS_ASCIIPB,
                              expected_result)
            self.assertEqual(expected_result, result)
            callback_called[0] += 1

        self.gce_api_client.get_firewall_rules.side_effect = [
            constants.DEFAULT_FIREWALL_API_RESPONSE,
            constants.EXPECTED_FIREWALL_API_RESPONSE]

        project_policies = [(self.project, self.policy)]
        self.batch_enforcer.run(project_policies,
                                new_result_callback=result_callback)

        self.assertEqual(1, callback_called[0])


if __name__ == '__main__':
    unittest.main()
