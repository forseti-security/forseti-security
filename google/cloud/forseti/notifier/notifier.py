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
"""Notifier service."""

import importlib
import inspect

# pylint: disable=line-too-long
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import findings
from google.cloud.forseti.notifier.notifiers import email_inventory_snapshot_summary as inv_summary
from google.cloud.forseti.notifier.notifiers import email_scanner_summary as scanner_summary
from google.cloud.forseti.notifier.notifiers.base_notification import BaseNotification
from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.scanner import dao as scanner_dao
# pylint: enable=line-too-long


LOGGER = logger.get_logger(__name__)


# pylint: disable=inconsistent-return-statements
def find_notifiers(notifier_name):
    """Get the first class in the given sub module

    Args:
        notifier_name (str): Name of the notifier.
    Return:
        class: The class in the sub module
    """
    try:
        module = importlib.import_module(
            'google.cloud.forseti.notifier.notifiers.{0}'.format(
                notifier_name))
        for filename in dir(module):
            obj = getattr(module, filename)

            if inspect.isclass(obj) \
                    and issubclass(obj, BaseNotification) \
                    and obj is not BaseNotification:
                return obj
    except ImportError as e:
        LOGGER.error('Can\'t import notifier %s: %s', notifier_name, e.message)

# pylint: enable=inconsistent-return-statements


def convert_to_timestamp(session, violations):
    """Convert violation created_at_datetime to timestamp string.
    Args:
        session (object): session object to work on.
        violations (sqlalchemy_object): List of violations as sqlalchemy
            row/record object with created_at_datetime.
    Returns:
        list: List of violations as sqlalchemy row/record object with
            created_at_datetime converted to timestamp string.
    """
    for violation in violations:
        session.expunge(violation)
        violation.created_at_datetime = (
            violation.created_at_datetime.strftime(
                string_formats.TIMESTAMP_TIMEZONE))

    return violations


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
        inv_email_notifier = inv_summary.EmailInventorySnapshotSummary(
            payload.get('sendgrid_api_key')
        )
        inv_email_notifier.run(
            payload.get('cycle_time'),
            payload.get('cycle_timestamp'),
            payload.get('snapshot_cycle_status'),
            payload.get('notifiers'),
            payload.get('email_sender'),
            payload.get('email_recipient')
        )
        return

    if message.get('status') == 'scanner_done':
        scanner_email_notifier = scanner_summary.EmailScannerSummary(
            payload.get('sendgrid_api_key')
        )
        scanner_email_notifier.run(
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


def run(inventory_index_id, progress_queue, service_config=None):
    """Run the notifier.

    Entry point when the notifier is run as a library.

    Args:
        inventory_index_id (str): Inventory index id.
        progress_queue (Queue): The progress queue.
        service_config (ServiceConfig): Forseti 2.0 service configs.

    Returns:
        int: Status code.
    """
    # pylint: disable=too-many-locals
    global_configs = service_config.get_global_config()
    notifier_configs = service_config.get_notifier_config()

    violations = None
    with service_config.scoped_session() as session:
        if not inventory_index_id:
            inventory_index_id = (
                DataAccess.get_latest_inventory_index_id(session))
        scanner_index_id = scanner_dao.get_latest_scanner_id(
            session, inventory_index_id)
        if not scanner_index_id:
            LOGGER.warn('No scanner index found.')

        # get violations
        violation_access = scanner_dao.ViolationAccess(session)
        violations = violation_access.list(scanner_index_id=scanner_index_id)
        violations = convert_to_timestamp(session, violations)
        violations_as_dict = []
        for violation in violations:
            violations_as_dict.append(
                scanner_dao.convert_sqlalchemy_object_to_dict(violation))
        violations = scanner_dao.map_by_resource(violations_as_dict)

        for retrieved_v in violations:
            log_message = ('Retrieved {} violations for resource \'{}\''.format(
                len(violations[retrieved_v]), retrieved_v))
            LOGGER.info(log_message)
            progress_queue.put(log_message)

        # build notification notifiers
        notifiers = []
        for resource in notifier_configs['resources']:
            if violations.get(resource['resource']) is None:
                log_message = 'Resource \'{}\' has no violations'.format(
                    resource['resource'])
                progress_queue.put(log_message)
                LOGGER.info(log_message)
                continue
            if not resource['should_notify']:
                LOGGER.debug('Not notifying for: %s', resource['resource'])
                continue
            for notifier in resource['notifiers']:
                log_message = (
                    'Running \'{}\' notifier for resource \'{}\''.format(
                        notifier['name'], resource['resource']))
                progress_queue.put(log_message)
                LOGGER.info(log_message)
                chosen_pipeline = find_notifiers(notifier['name'])
                notifiers.append(chosen_pipeline(
                    resource['resource'], inventory_index_id,
                    violations[resource['resource']], global_configs,
                    notifier_configs, notifier['configuration']))

        # Run the notifiers.
        for notifier in notifiers:
            notifier.run()

        if (notifier_configs.get('violation') and
                notifier_configs.get('violation').get('findings')):
            findings_configs = notifier_configs.get('violation').get('findings')
            if findings_configs.get('enabled'):
                findings.Findingsnotifier().run(
                    violations_as_dict, findings_configs.get('gcs_path'))

        log_message = 'Notification completed!'
        progress_queue.put(log_message)
        progress_queue.put(None)
        LOGGER.info(log_message)
        return 0
