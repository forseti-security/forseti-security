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

"""Enforcer runner.

Usage for enforcing a single project's firewall:

  $ forseti_enforcer --enforce_project <project_id> \\
      --policy_file <policy file path>

"""
import argparse
import sys
import threading

from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.enforcer import batch_enforcer
from google.cloud.forseti.enforcer import enforcer_log_pb2

LOGGER = logger.get_logger(__name__)


class Error(Exception):
    """Base error class for the module."""


class InvalidParsedPolicyFileError(Error):
    """An invalid policy file was parsed."""


def initialize_batch_enforcer(global_configs, concurrent_threads,
                              max_write_threads, max_running_operations,
                              dry_run):
    """Initialize and return a BatchFirewallEnforcer object.

    Args:
        global_configs (dict): Global configurations.
        concurrent_threads (str): The number of parallel enforcement threads to
            execute.
        max_write_threads (str): The maximum number of enforcement threads that
            can be actively updating project firewalls.
        max_running_operations (str): [DEPRECATED] The maximum number of write
            operations per enforcement thread.
        dry_run (boolean): If True, will simply log what action would have been
            taken without actually applying any modifications.

    Returns:
        BatchFirewallEnforcer: A BatchFirewallEnforcer instance.
    """
    if max_running_operations:
        LOGGER.warn('Deprecated argument max_running_operations set.')

    if max_write_threads:
        project_sema = threading.BoundedSemaphore(value=max_write_threads)
    else:
        project_sema = None

    enforcer = batch_enforcer.BatchFirewallEnforcer(
        global_configs=global_configs,
        dry_run=dry_run,
        concurrent_workers=concurrent_threads,
        project_sema=project_sema)

    return enforcer


def enforce_single_project(enforcer, project_id, policy_filename):
    """Runs the enforcer on a single project.

    Args:
        enforcer (BatchFirewallEnforcer): An instance of the
            batch_enforcer.BatchFirewallEnforcer class.
        project_id (str): The project to enforce.
        policy_filename (str): The json encoded file to read the firewall policy
            from.

    Raises:
        InvalidParsedPolicyFileError: When the policy file can't be parsed.

    Returns:
        EnforcerLogProto: A instance of the proto.
    """
    policy = file_loader.read_and_parse_file(policy_filename)

    if not isinstance(policy, list):
        raise InvalidParsedPolicyFileError(
            'Invalid parsed policy file: found %s expected list' %
            type(policy))

    project_policies = [(project_id, policy)]

    enforcer_results = enforcer.run(project_policies)

    for result in enforcer_results.results:
        result.gce_firewall_enforcement.policy_path = policy_filename
        result.run_context = enforcer_log_pb2.ENFORCER_ONE_PROJECT

    return enforcer_results


def main():
    """The main entry point for Forseti Security Enforcer runner."""
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument(
        '--forseti_config',
        default='/home/ubuntu/forseti-security/configs/'
                'forseti_conf_server.yaml',
        help='Fully qualified path and filename of the Forseti config file.')

    arg_parser.add_argument(
        '--enforce_project', default=None,
        help='A single projectId to enforce the firewall on.'
             ' Must be used with the policy_file flag.')

    arg_parser.add_argument(
        '--policy_file', default=None,
        help='A json encoded policy file to enforce,'
             ' must contain a list of Firewall resources to'
             'apply to the project. If in a GCS bucket, '
             'include full path, e.g. '
             '"gs://<bucketname>/path/to/file".')

    arg_parser.add_argument(
        '--dry_run', default=False,
        help='If True will simulate the changes and not change'
             'any policies.')

    arg_parser.add_argument(
        '--concurrent_threads', default=10,
        help='The number concurrent worker threads to use.')

    arg_parser.add_argument(
        '--maximum_firewall_write_operations', default=10,
        help='The maximum number of in flight write operations'
             'on project firewalls. Each running thread is '
             'allowed up to this many running operations, '
             'so to limit the over all number of operations, '
             'limit the number of write threads using the'
             ' maximum_project_writer_threads flag.')

    arg_parser.add_argument(
        '--maximum_project_writer_threads', default=1,
        help='The maximum number of projects with active write '
             'operations on project firewalls.')

    flags = vars(arg_parser.parse_args())

    forseti_config = flags['forseti_config']

    if forseti_config is None:
        LOGGER.error('Path to Forseti Security config needs to be specified.')
        sys.exit()

    try:
        configs = file_loader.read_and_parse_file(forseti_config)
    except IOError:
        LOGGER.exception('Unable to open Forseti Security config file. '
                         'Please check your path and filename and try again.')
        sys.exit()
    global_configs = configs.get('global')

    enforcer = initialize_batch_enforcer(
        global_configs, flags['concurrent_threads'],
        flags['maximum_project_writer_threads'],
        flags['maximum_firewall_write_operations'],
        flags['dry_run']
    )

    if flags['enforce_project'] and flags['policy_file']:
        enforcer_results = enforce_single_project(enforcer,
                                                  flags['enforce_project'],
                                                  flags['policy_file'])

        print enforcer_results

    else:
        print 'Batch mode not implemented yet.'


if __name__ == '__main__':
    main()
