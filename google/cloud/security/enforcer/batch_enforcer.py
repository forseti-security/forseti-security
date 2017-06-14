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

"""Manages enforcement of policies for multiple cloud projects in parallel."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import concurrent.futures
from google.apputils import datelib

from google.cloud.security.common.gcp_api import compute
from google.cloud.security.common.util import log_util
from google.cloud.security.enforcer import enforcer_log_pb2
from google.cloud.security.enforcer import project_enforcer

STATUS_SUCCESS = enforcer_log_pb2.SUCCESS
STATUS_ERROR = enforcer_log_pb2.ERROR
STATUS_SKIPPED = enforcer_log_pb2.SKIPPED
STATUS_DELETED = enforcer_log_pb2.PROJECT_DELETED

LOGGER = log_util.get_logger(__name__)


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc


class BatchFirewallEnforcer(object):
    """Manage the parallel enforcement of firewall policies across projects."""

    def __init__(self,
                 dry_run=False,
                 concurrent_workers=1,
                 project_sema=None,
                 max_running_operations=0):
        """Initialize.

        Args:
          dry_run: If True, will simply log what action would have been taken
              without actually applying any modifications.
          concurrent_workers: The number of parallel enforcement threads to
              execute.
          project_sema: An optional semaphore object, used to limit the number
              of concurrent projects getting written to.
          max_running_operations: Used to limit the number of concurrent write
              operations on a single project's firewall rules. Set to 0 to
              allow unlimited in flight asynchronous operations.
        """
        self.enforcement_log = enforcer_log_pb2.EnforcerLog()
        self._dry_run = dry_run
        self._concurrent_workers = concurrent_workers

        self._project_sema = project_sema
        self._max_running_operations = max_running_operations

        self.compute = compute.ComputeClient()

        self.batch_id = None

    def run(self, project_policies, prechange_callback=None,
            new_result_callback=None):
        """Runs the enforcer over all projects passed in to the function.

        Args:
          project_policies: An iterable of (project_id, firewall_policy)
              tuples to enforce or a dictionary in the format
              {project_id: firewall_policy}

          prechange_callback: A callback function that will get called if the
              firewall policy for a project does not match the expected policy,
              before any changes are actually applied. If the callback returns
              False then no changes will be made to the project. If it returns
              True then the changes will be pushed.

              See FirewallEnforcer.apply_firewall() docstring for more details.

          new_result_callback: An optional function to call with each new result
              proto message as they are returned from a ProjectEnforcer thread.

        Returns:
          The EnforcerLog proto for the last run, including individual results
          for each project, and a summary of all results.
        """
        if self._dry_run:
            LOGGER.info('Simulating changes')

        if isinstance(project_policies, dict):
            project_policies = project_policies.items()

        # Get a 64 bit int to use as the unique batch ID for this run.
        self.batch_id = datelib.Timestamp.now().AsMicroTimestamp()

        self.enforcement_log.Clear()
        self.enforcement_log.summary.batch_id = self.batch_id
        self.enforcement_log.summary.projects_total = len(project_policies)

        started_timestamp = datelib.Timestamp.now()
        LOGGER.info('starting enforcement wave: %s', started_timestamp)

        projects_enforced_count = self._enforce_projects(project_policies,
                                                         prechange_callback,
                                                         new_result_callback)

        finished_timestamp = datelib.Timestamp.now()
        total_time = (finished_timestamp.AsSecondsSinceEpoch() -
                      started_timestamp.AsSecondsSinceEpoch())

        LOGGER.info('finished wave in %i seconds', total_time)

        self.enforcement_log.summary.timestamp_start_msec = (
            started_timestamp.AsMicroTimestamp())
        self.enforcement_log.summary.timestamp_end_msec = (
            finished_timestamp.AsMicroTimestamp())

        self._summarize_results()

        if not projects_enforced_count:
            LOGGER.warn('No projects enforced on the last run, exiting.')

        return self.enforcement_log

    def _enforce_projects(self, project_policies, prechange_callback=None,
                          new_result_callback=None):
        """Do a single enforcement run on the projects.

        Args:
          project_policies: An iterable of (project_id, firewall_policy) tuples
              to enforce.
          prechange_callback: See docstring for self.Run().
          new_result_callback: See docstring for self.Run().

        Returns:
          The number of projects that were enforced.
        """
        projects_enforced_count = 0
        future_to_key = {}
        with (concurrent.futures.ThreadPoolExecutor(
            max_workers=self._concurrent_workers)) as executor:
            for (project_id, firewall_policy) in project_policies:
                future = executor.submit(self._enforce_project, project_id,
                                         firewall_policy, prechange_callback)
                future_to_key[future] = project_id

            for future in concurrent.futures.as_completed(future_to_key):
                project_id = future_to_key[future]
                LOGGER.debug('Project %s finished enforcement run.',
                             project_id)
                projects_enforced_count += 1

                result = self.enforcement_log.results.add()
                result.CopyFrom(future.result())

                # Make sure all results have the current batch_id set
                result.batch_id = self.batch_id
                result.run_context = enforcer_log_pb2.ENFORCER_BATCH

                if new_result_callback:
                    new_result_callback(result)

        return projects_enforced_count

    def _enforce_project(self, project_id, firewall_policy, prechange_callback):
        """Enforces the policy on the project.

        Args:
          project_id: The project id to enforce.
          firewall_policy: A list of rules which are used to construct a
              fe.FirewallRules object of expected rules to enforce.
          prechange_callback: See docstring for self.Run().

        Returns:
          A GceEnforcerResult proto
        """
        enforcer = project_enforcer.ProjectEnforcer(
            project_id,
            dry_run=self._dry_run,
            project_sema=self._project_sema,
            max_running_operations=self._max_running_operations)

        result = enforcer.enforce_firewall_policy(
            firewall_policy,
            compute_service=self.compute.service,
            prechange_callback=prechange_callback)

        return result

    def _summarize_results(self):
        """Parse enforcement results into the BatchResult summary proto."""
        for result in self.enforcement_log.results:
            if result.status == STATUS_ERROR:
                self.enforcement_log.summary.projects_error += 1
            elif result.status in (STATUS_SUCCESS, STATUS_DELETED):
                # Treat deleted projects as success, they will be removed from
                # the queue automatically on the next run of the QueueManager
                # job.
                self.enforcement_log.summary.projects_success += 1

            if result.gce_firewall_enforcement.rules_modified_count:
                self.enforcement_log.summary.projects_changed += 1

        self.enforcement_log.summary.projects_unchanged = (
            self.enforcement_log.summary.projects_total -
            self.enforcement_log.summary.projects_changed)
