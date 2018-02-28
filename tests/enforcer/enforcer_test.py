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

"""Tests for google.cloud.forseti.enforcer.enforcer."""

import mock
import unittest

from tests.enforcer import testing_constants as constants
from tests.unittest_utils import ForsetiTestCase
from google.protobuf import text_format
from tests.unittest_utils import get_datafile_path

from google.cloud.forseti.enforcer import enforcer_log_pb2
from google.cloud.forseti.enforcer import enforcer

# Used anywhere a real timestamp could be generated to ensure consistent
# comparisons in tests
MOCK_TIMESTAMP = 1234567890


class EnforcerTest(ForsetiTestCase):
    """Extended unit tests for BatchFirewallEnforcer class."""

    def setUp(self):
        """Set up."""
        self.mock_compute = mock.patch.object(enforcer.batch_enforcer.compute,
                                              'ComputeClient').start()

        self.gce_service = self.mock_compute().service
        self.gce_service.networks().list().execute.return_value = (
            constants.SAMPLE_TEST_NETWORK_SELFLINK)

        self.project = constants.TEST_PROJECT

        self.mock_time = mock.patch.object(enforcer.batch_enforcer.datelib,
                                           'Timestamp').start()

        self.mock_time.now().AsMicroTimestamp.return_value = MOCK_TIMESTAMP
        self.mock_time.now().AsSecondsSinceEpoch.return_value = MOCK_TIMESTAMP

        self.enforcer = enforcer.initialize_batch_enforcer(
            {},
            concurrent_threads=1,
            max_write_threads=1,
            max_running_operations=0,
            dry_run=True)

        self.expected_summary = (
            enforcer_log_pb2.BatchResult(
                batch_id=MOCK_TIMESTAMP,
                timestamp_start_msec=MOCK_TIMESTAMP,
                timestamp_end_msec=MOCK_TIMESTAMP))

        self.addCleanup(mock.patch.stopall)

    def test_enforce_single_project(self):
      """Verifies enforce_single_project returns the correct results.

      Setup:
        * Set API calls to return the different firewall rules from the new
          policy on the first call, and the expected new firewall rules on the
          second call.
        * Load a mock policy file.
        * Create a temporary directory for writing the dremel recordio table out
          to.
        * Send the policy and project to EnforceSingleProject.

      Expected Results:
        * The results proto returned matches the expected results.
      """
      self.gce_service.firewalls().list().execute.side_effect = [
          constants.DEFAULT_FIREWALL_API_RESPONSE,
          constants.EXPECTED_FIREWALL_API_RESPONSE]

      policy_filename = get_datafile_path(__file__, 'sample_policy.json')

      results = enforcer.enforce_single_project(self.enforcer, self.project,
                                                policy_filename)

      self.expected_summary.projects_total = 1
      self.expected_summary.projects_success = 1
      self.expected_summary.projects_changed = 1
      self.expected_summary.projects_unchanged = 0

      self.assertEqual(self.expected_summary, results.summary)

      expected_results = enforcer_log_pb2.ProjectResult()
      text_format.Merge(constants.SAMPLE_ENFORCER_PROJECTRESULTS_ASCIIPB,
                        expected_results)
      expected_results.run_context = enforcer_log_pb2.ENFORCER_ONE_PROJECT
      expected_results.gce_firewall_enforcement.policy_path = policy_filename

      project_result = results.results[0]

      self.assertEqual(expected_results, project_result)

    def test_enforcer_raises_exception_with_invalid_json_policy(self):
        """Verifies json parsed correct as a list of dictionaries.

        Setup:
          * Load an invalid json file (no list).
          * Give it to enforcer to parse and load

        Expected Results:
          * Enforcer should raise InvalidParsedPolicyFileError
        """
        policy_filename = get_datafile_path(__file__, 'invalid_sample_policy.json')
        with self.assertRaises(enforcer.InvalidParsedPolicyFileError) as r:
            enforcer.enforce_single_project(
                self.enforcer, self.project, policy_filename)


if __name__ == '__main__':
    unittest.main()
