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

# pylint: disable=line-too-long
from google.apputils import app
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.notifier.pipelines.base_notification_pipeline import BaseNotificationPipeline
from google.cloud.forseti.notifier.pipelines import email_inventory_snapshot_summary_pipeline as inv_summary
from google.cloud.forseti.notifier.pipelines import email_scanner_summary_pipeline as scanner_summary
from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.scanner import dao as scanner_dao
# pylint: enable=line-too-long


# Setup flags
FLAGS = flags.FLAGS

flags.DEFINE_string(
    'inventory_index_id',
    '-1',
    'Inventory index id')


LOGGER = log_util.get_logger(__name__)
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'

# pylint: disable=inconsistent-return-statements
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
# pylint: enable=inconsistent-return-statements

def _get_latest_inventory_index_id(service_config):
    """Get latest snapshot timestamp.

    Args:
        service_config (dict): 2.0 service configs.

    Returns:
        string: The latest snapshot timestamp.
    """

    allowed_status = ('SUCCESS', 'PARTIAL_SUCCESS')
    inventory_index_id = ''
    with service_config.scoped_session() as session:
        for item in DataAccess.list(session):
            if item.status in allowed_status:
                inventory_index_id = item.id
    LOGGER.info(
        'Latest success/partial_success inventory id is: %s',
        inventory_index_id)
    return inventory_index_id

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

def run(inventory_index_id, service_config=None):
    """Run the notifier.

    Entry point when the notifier is run as a library.

    Args:
        inventory_index_id (str): Inventory index id.
        service_config (ServiceConfig): Forseti 2.0 service configs

    Returns:
        int: Status code.
    """
    try:
        configs = file_loader.read_and_parse_file(
            service_config.forseti_config_file_path)
    except IOError:
        LOGGER.error('Unable to open Forseti Security config file. '
                     'Please check your path and filename and try again.')
        sys.exit()
    global_configs = configs.get('global')
    notifier_configs = configs.get('notifier')

    if not inventory_index_id:
        inventory_index_id = _get_latest_inventory_index_id(service_config)

    # get violations
    violation_access_cls = scanner_dao.define_violation(
        service_config.engine)
    violation_access = violation_access_cls(service_config.engine)
    service_config.violation_access = violation_access
    violations = violation_access.list(inventory_index_id)

    violations_as_dict = []
    for violation in violations:
        violations_as_dict.append(
            scanner_dao.convert_sqlalchemy_object_to_dict(violation))

    violations = scanner_dao.map_by_resource(violations_as_dict)

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
                                             inventory_index_id,
                                             violations[resource['resource']],
                                             global_configs,
                                             notifier_configs,
                                             pipeline['configuration']))

    # run the pipelines
    for pipeline in pipelines:
        pipeline.run()

    LOGGER.info('Notification complete!')
    return 0


def main(_):
    """Entry point when the notifier is run as an executable.

    Args:
        _ (list): args that aren't used

    Returns:
        int: Status code.
    """

    run(FLAGS.inventory_index_id)
    return 0


if __name__ == '__main__':
    app.run()
