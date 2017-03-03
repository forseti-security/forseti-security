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

"""Enforcer runner.

Usage for enforcing a single project's firewall:

  $ forseti_enforcer --enforce_project <project_id> \\
      --policy_file <policy file path>

"""

import gflags as flags
import threading
from google.apputils import app

from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.enforcer import batch_enforcer
from google.cloud.security.enforcer import enforcer_log_pb2

flags.DEFINE_string('enforce_project', None,
                    'A single projectId to enforce the firewall on. Must be '
                    'used with the policy_file flag.')

flags.DEFINE_string('policy_file', None,
                    'A json encoded policy file to enforce, must contain a '
                    'list of Firewall resources to apply to the project. '
                    'If in a GCS bucket, include full path, e.g. '
                    '"gs://<bucketname>/path/to/file".')

flags.DEFINE_boolean('dry_run', False,
                     'If True will simulate the changes and not change any '
                     'policies.')

flags.DEFINE_integer('concurrent_threads', 10,
                     'The number concurrent worker threads to use.',
                     lower_bound=1, upper_bound=50)

flags.DEFINE_integer('maximum_firewall_write_operations', 10,
                     'The maximum number of in flight write operations on '
                     'project firewalls. Each running thread is allowed up to '
                     'this many running operations, so to limit the over all '
                     'number of operations, limit the number of write threads '
                     'using the maximum_project_writer_threads flag.',
                     lower_bound=0, upper_bound=50)

flags.DEFINE_integer('maximum_project_writer_threads', 1,
                     'The maximum number of projects with active write '
                     'operations on project firewalls.',
                     lower_bound=0, upper_bound=50)

# Setup flags
FLAGS = flags.FLAGS


def initialize_batch_enforcer(concurrent_threads, max_write_threads,
                              max_running_operations, dry_run):
    """Initialize and return a BatchFirewallEnforcer object.

    Args:
      concurrent_threads: The number of parallel enforcement threads to execute.
      max_write_threads: The maximum number of enforcement threads that can be
          actively updating project firewalls.
      max_running_operations: The maximum number of write operations per
          enforcement thread.
      dry_run: If True, will simply log what action would have been taken
          without actually applying any modifications.

    Returns:
      A BatchFirewallEnforcer instance.
    """
    if max_write_threads:
        project_sema = threading.BoundedSemaphore(value=max_write_threads)
    else:
        project_sema = None

    enforcer = batch_enforcer.BatchFirewallEnforcer(
        dry_run=dry_run,
        concurrent_workers=concurrent_threads,
        project_sema=project_sema,
        max_running_operations=max_running_operations)

    return enforcer


def enforce_single_project(enforcer, project_id, policy_filename):
    """Runs the enforcer on a single project.

    Args:
      enforcer: An instance of the batch_enforcer.BatchFirewallEnforcer class.
      project_id: The project to enforce.
      policy_filename: The json encoded file to read the firewall policy from.

    Returns:
      The EnforcerLog proto for the last run, including individual results for
      the enforced project, and a summary of the run.
    """
    policy = file_loader.read_and_parse_file(policy_filename)
    project_policies = [(project_id, policy)]

    enforcer_results = enforcer.run(project_policies)

    for result in enforcer_results.results:
        result.gce_firewall_enforcement.policy_path = policy_filename
        result.run_context = enforcer_log_pb2.ENFORCER_ONE_PROJECT

    return enforcer_results


def main(argv):
    del argv

    enforcer = initialize_batch_enforcer(
            FLAGS.concurrent_threads, FLAGS.maximum_project_writer_threads,
            FLAGS.maximum_firewall_write_operations, FLAGS.dry_run)

    if FLAGS.enforce_project and FLAGS.policy_file:
        enforcer_results = enforce_single_project(enforcer,
                                                  FLAGS.enforce_project,
                                                  FLAGS.policy_file)

        print(enforcer_results)

    else:
        print('Batch mode not implemented yet.')


if __name__ == '__main__':
    app.run()
