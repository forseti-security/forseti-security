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
"""Notifier.

Usage:

  $ forseti_notifier --db_host <Cloud SQL database hostname/IP> \\
      --db_user <Cloud SQL database user> \\
      --db_name <Cloud SQL database name (required)> \\
      --config <Notification configuration> \\
      --timestamp <Snapshot timestamp to search for violations>
"""

import importlib
import inspect
import sys
import gflags as flags

# pylint: disable=line-too-long,inconsistent-return-statements

from google.apputils import app
from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access import errors as db_errors
from google.cloud.forseti.common.data_access import violation_dao
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.notifier.pipelines.base_notification_pipeline import BaseNotificationPipeline
from google.cloud.forseti.notifier.pipelines import email_inventory_snapshot_summary_pipeline as inv_summary
from google.cloud.forseti.notifier.pipelines import email_scanner_summary_pipeline as scanner_summary


# Setup flags
FLAGS = flags.FLAGS

# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# Example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py
flags.DEFINE_string('timestamp', None, 'Snapshot timestamp')
flags.DEFINE_string('config', None, 'Config file to use', short_name='c')

# Hack to make the test pass due to duplicate flag error here
# and inventory_loader.
# TODO: Find a way to remove this try/except, possibly dividing the tests
# into different test suites.
try:
    flags.DEFINE_string(
        'forseti_config',
        '/home/ubuntu/forseti-security/configs/forseti_conf.yaml',
        'Fully qualified path and filename of the Forseti config file.')
except flags.DuplicateFlagError:
    pass

LOGGER = log_util.get_logger(__name__)
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


def find_pipelines(pipeline_name):
    """Get the first class in the given sub module

    Args:
        pipeline_name (str): Name of the pipeline.

    Return:
        class: The class in the sub module
    """
    try:
        module = importlib.import_module(
            'google.cloud.forseti.notifier.pipelines.{0}'.format(
                pipeline_name))
        for filename in dir(module):
            obj = getattr(module, filename)

            if inspect.isclass(obj) \
               and issubclass(obj, BaseNotificationPipeline) \
               and obj is not BaseNotificationPipeline:
                return obj
    except ImportError, e:
        LOGGER.error('Can\'t import pipeline %s: %s', pipeline_name, e.message)


def _get_timestamp(global_configs, statuses=('SUCCESS', 'PARTIAL_SUCCESS')):
    """Get latest snapshot timestamp.

    Args:
        global_configs (dict): Global configurations.
        statuses (tuple): Snapshot statues.

    Returns:
        string: The latest snapshot timestamp.
    """

    latest_timestamp = None
    try:
        current_dao = dao.Dao(global_configs)
        latest_timestamp = current_dao.get_latest_snapshot_timestamp(statuses)
    except db_errors.MySQLError as err:
        LOGGER.error('Error getting latest snapshot timestamp: %s', err)

    return latest_timestamp

def process(message):
    """Process messages about what notifications to send.

    Args:
        message (dict): Message with payload in dict.
            The payload will be different depending on the sender
            of the message.

            Example:
                {'status': 'foobar_done',
                 'payload': {}}
    """
    payload = message.get('payload')

    if message.get('status') == 'inventory_done':
        inv_email_pipeline = inv_summary.EmailInventorySnapshotSummaryPipeline(
            payload.get('sendgrid_api_key'))
        inv_email_pipeline.run(
            payload.get('cycle_time'),
            payload.get('cycle_timestamp'),
            payload.get('snapshot_cycle_status'),
            payload.get('pipelines'),
            payload.get('email_sender'),
            payload.get('email_recipient')
        )
        return

    if message.get('status') == 'scanner_done':
        scanner_email_pipeline = scanner_summary.EmailScannerSummaryPipeline(
            payload.get('sendgrid_api_key'))
        scanner_email_pipeline.run(
            payload.get('output_csv_name'),
            payload.get('output_filename'),
            payload.get('now_utc'),
            payload.get('all_violations'),
            payload.get('resource_counts'),
            payload.get('violation_errors'),
            payload.get('email_sender'),
            payload.get('email_recipient'),
            payload.get('email_description'))
        return

def main(_):
    """Main function.

        Args:
            _ (obj): Result of the last expression evaluated in the interpreter.
    """
    notifier_flags = FLAGS.FlagValuesDict()

    forseti_config = notifier_flags.get('forseti_config')

    if forseti_config is None:
        LOGGER.error('Path to Forseti Security config needs to be specified.')
        sys.exit()

    try:
        configs = file_loader.read_and_parse_file(forseti_config)
    except IOError:
        LOGGER.error('Unable to open Forseti Security config file. '
                     'Please check your path and filename and try again.')
        sys.exit()
    global_configs = configs.get('global')
    notifier_configs = configs.get('notifier')

    timestamp = notifier_configs.get('timestamp')
    if timestamp is None:
        timestamp = _get_timestamp(global_configs)

    # get violations
    v_dao = violation_dao.ViolationDao(global_configs)
    violations = {}
    try:
        violations = violation_dao.map_by_resource(
            v_dao.get_all_violations(timestamp))
    except db_errors.MySQLError, e:
        # even if an error is raised we still want to continue execution
        # this is because if we don't have violations the Mysql table
        # is not present and an error is thrown
        LOGGER.error('get_all_violations error: %s', e.message)

    for retrieved_v in violations:
        LOGGER.info('retrieved %d violations for resource \'%s\'',
                    len(violations[retrieved_v]), retrieved_v)

    # build notification pipelines
    pipelines = []
    for resource in notifier_configs['resources']:
        if violations.get(resource['resource']) is None:
            LOGGER.warn('The resource name \'%s\' has no violations, '
                        'skipping', resource['resource'])
            continue
        if not violations[resource['resource']]:
            LOGGER.debug('No violations for: %s', resource['resource'])
            continue
        if not resource['should_notify']:
            continue
        for pipeline in resource['pipelines']:
            LOGGER.info('Running \'%s\' pipeline for resource \'%s\'',
                        pipeline['name'], resource['resource'])
            chosen_pipeline = find_pipelines(pipeline['name'])
            pipelines.append(chosen_pipeline(resource['resource'],
                                             timestamp,
                                             violations[resource['resource']],
                                             global_configs,
                                             notifier_configs,
                                             pipeline['configuration']))

    # run the pipelines
    for pipeline in pipelines:
        pipeline.run()


if __name__ == '__main__':
    app.run()
