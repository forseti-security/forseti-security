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

"""Manages enforcement of policies for multiple cloud projects in parallel."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
import threading

import concurrent.futures

from google.cloud.forseti.common.gcp_api import compute
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.enforcer import enforcer_log_pb2
from google.cloud.forseti.enforcer import project_enforcer

STATUS_SUCCESS = enforcer_log_pb2.SUCCESS
STATUS_ERROR = enforcer_log_pb2.ERROR
STATUS_SKIPPED = enforcer_log_pb2.SKIPPED
STATUS_DELETED = enforcer_log_pb2.PROJECT_DELETED

LOGGER = logger.get_logger(__name__)

# Per thread storage.
LOCAL_THREAD = threading.local()


class BatchFirewallEnforcer(object):
    """Manage the parallel enforcement of firewall policies across projects."""

    def __init__(self,
                 global_configs=None,
                 dry_run=False,
                 concurrent_workers=1,
                 project_sema=None,
                 max_running_operations=0):
        """Initialize.

        Args:
          global_configs (dict): Global configurations.
          dry_run (bool): If True, will simply log what action would have been
              taken without actually applying any modifications.
          concurrent_workers (int): The number of parallel enforcement threads
              to execute.
          project_sema (threading.BoundedSemaphore): An optional semaphore
              object, used to limit the number of concurrent projects getting
              written to.
          max_running_operations (int): [DEPRECATED] Used to limit the number of
              concurrent write operations on a single project's firewall rules.
              Set to 0 to allow unlimited in flight asynchronous operations.
        """
        self.global_configs = global_configs
        self.enforcement_log = enforcer_log_pb2.EnforcerLog()
        self._dry_run = dry_run
        self._concurrent_workers = concurrent_workers

        self._project_sema = project_sema

        if max_running_operations:
            LOGGER.warn(
                'Max running operations is deprecated. Argument ignored.')
        self._max_running_operations = None
        self._local = LOCAL_THREAD

    @property
    def compute_client(self):
        """A thread local instance of compute.ComputeClient.

        Returns:
            compute.ComputeClient: A Compute API client instance.
        """
        if not hasattr(self._local, 'compute_client'):
            self._local.compute_client = compute.ComputeClient(
                self.global_configs, dry_run=self._dry_run)

        return self._local.compute_client

    def run(self, project_policies, prechange_callback=None,
            new_result_callback=None, add_rule_callback=None):
        """Runs the enforcer over all projects passed in to the function.

        Args:
          project_policies (iterable): An iterable of
              (project_id, firewall_policy) tuples to enforce or a dictionary
              in the format {project_id: firewall_policy}

          prechange_callback (Callable): A callback function that will get
              called if the firewall policy for a project does not match the
              expected policy, before any changes are actually applied. If the
              callback returns False then no changes will be made to the
              project. If it returns True then the changes will be pushed.

              See FirewallEnforcer.apply_firewall() docstring for more details.

          new_result_callback (Callable): An optional function to call with each
              new result proto message as they are returned from a
              ProjectEnforcer thread.

          add_rule_callback (Callable): A callback function that checks whether
              a firewall rule should be applied. If the callback returns False,
              that rule will not be modified.

        Returns:
          enforcer_log_pb2.EnforcerLog: The EnforcerLog proto for the last run,
          including individual results for each project, and a summary of all
          results.
        """
        if self._dry_run:
            LOGGER.info('Simulating changes')

        if isinstance(project_policies, dict):
            project_policies = project_policies.items()

        self.enforcement_log.Clear()
        self.enforcement_log.summary.projects_total = len(project_policies)

        started_time = date_time.get_utc_now_datetime()
        LOGGER.info('starting enforcement wave: %s', started_time)

        projects_enforced_count = self._enforce_projects(project_policies,
                                                         prechange_callback,
                                                         new_result_callback,
                                                         add_rule_callback)

        finished_time = date_time.get_utc_now_datetime()

        started_timestamp = date_time.get_utc_now_unix_timestamp(started_time)
        finished_timestamp = date_time.get_utc_now_unix_timestamp(finished_time)
        total_time = finished_timestamp - started_timestamp

        LOGGER.info('finished wave in %i seconds', total_time)

        self.enforcement_log.summary.timestamp_start_msec = (
            date_time.get_utc_now_microtimestamp(started_time))
        self.enforcement_log.summary.timestamp_end_msec = (
            date_time.get_utc_now_microtimestamp(finished_time))

        self._summarize_results()

        if not projects_enforced_count:
            LOGGER.warn('No projects enforced on the last run, exiting.')

        return self.enforcement_log

    def _enforce_projects(self, project_policies, prechange_callback=None,
                          new_result_callback=None, add_rule_callback=None):
        """Do a single enforcement run on the projects.

        Args:
          project_policies (iterable): An iterable of
              (project_id, firewall_policy) tuples to enforce.
          prechange_callback (Callable): See docstring for self.Run().
          new_result_callback (Callable): See docstring for self.Run().
          add_rule_callback (Callable): See docstring for self.Run().

        Returns:
          int: The number of projects that were enforced.
        """
        # Get a 64 bit int to use as the unique batch ID for this run.
        batch_id = date_time.get_utc_now_microtimestamp()
        self.enforcement_log.summary.batch_id = batch_id

        projects_enforced_count = 0
        future_to_key = {}
        with (
            concurrent.futures.ThreadPoolExecutor(
                max_workers=self._concurrent_workers)) as executor:
            for (project_id, firewall_policy) in project_policies:
                future = executor.submit(self._enforce_project, project_id,
                                         firewall_policy, prechange_callback,
                                         add_rule_callback)
                future_to_key[future] = project_id

            for future in concurrent.futures.as_completed(future_to_key):
                project_id = future_to_key[future]
                LOGGER.debug('Project %s finished enforcement run.',
                             project_id)
                projects_enforced_count += 1

                result = self.enforcement_log.results.add()
                result.CopyFrom(future.result())

                # Make sure all results have the current batch_id set
                result.batch_id = batch_id
                result.run_context = enforcer_log_pb2.ENFORCER_BATCH

                if new_result_callback:
                    new_result_callback(result)

        return projects_enforced_count

    def _enforce_project(self, project_id, firewall_policy,
                         prechange_callback=None, add_rule_callback=None):
        """Enforces the policy on the project.

        Args:
          project_id (str): The project id to enforce.
          firewall_policy (list): A list of rules which are used to construct a
              fe.FirewallRules object of expected rules to enforce.
          prechange_callback (Callable): See docstring for self.Run().
          add_rule_callback (Callable): See docstring for self.Run().

        Returns:
          enforcer_log_pb2.GceFirewallEnforcementResult: The result proto.
        """
        enforcer = project_enforcer.ProjectEnforcer(
            project_id,
            compute_client=self.compute_client,
            dry_run=self._dry_run,
            project_sema=self._project_sema)

        result = enforcer.enforce_firewall_policy(
            firewall_policy,
            prechange_callback=prechange_callback,
            add_rule_callback=add_rule_callback)

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
