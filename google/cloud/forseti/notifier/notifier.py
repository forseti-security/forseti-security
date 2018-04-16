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
from google.cloud.forseti.notifier.notifiers.gcs_inv_summary import (
    GcsInvSummary)
from google.cloud.forseti.notifier.notifiers.base_notification import BaseNotification
from google.cloud.forseti.services.inventory.storage import DataAccess
from google.cloud.forseti.services.inventory.storage import InventoryIndex
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


def convert_to_timestamp(violations):
    """Convert violation created_at_datetime to timestamp string.
    Args:
        violations (sqlalchemy_object): List of violations as sqlalchemy
            row/record object with created_at_datetime.
    Returns:
        list: List of violations as sqlalchemy row/record object with
            created_at_datetime converted to timestamp string.
    """
    for violation in violations:
        violation.created_at_datetime = (
            violation.created_at_datetime.strftime(
                string_formats.TIMESTAMP_TIMEZONE))

    return violations


def inv_summary_notify(inv_index_id, service_config):
    """Emit an inventory summary notification if/as needed.

    Args:
        inv_index_id (str): Inventory index id.
        service_config (ServiceConfig): Forseti 2.0 service configs.
    """
    notifier_config = service_config.get_notifier_config()
    if not notifier_config.get('inventory'):
        return

    if not notifier_config.get('inventory').get('summary'):
        return

    notifier_config = notifier_config.get('inventory').get('summary')

    if not notifier_config.get('enabled'):
        LOGGER.info('inventory summary notifications are turned off.')
        return

    if not notifier_config.get('gcs_path'):
        LOGGER.error('"gcs_path" not set for inventory summary notifier.')
        return

    with service_config.scoped_session() as session:
        inv_index = session.query(InventoryIndex).get(inv_index_id)
        if inv_index.notified_at_datetime:
            LOGGER.info(
                'Inventory summary notification already sent (%s).',
                inv_index.notified_at_datetime)
            return

        summary_data = inv_index.get_summary(session)
        if not summary_data:
            LOGGER.warn('No inventory summary data found.')
            return

        inv_summary = []
        for key, value in summary_data.iteritems():
            inv_summary.append(dict(resource_type=key, count=value))

        notifier = GcsInvSummary(inv_index_id, inv_summary, notifier_config)
        notifier.run()
        inv_index.mark_notified(session)


def run(inv_index_id, progress_queue, service_config=None):
    """Run the notifier.

    Entry point when the notifier is run as a library.

    Args:
        inv_index_id (str): Inventory index id.
        progress_queue (Queue): The progress queue.
        service_config (ServiceConfig): Forseti 2.0 service configs.

    Returns:
        int: Status code.
    """
    # pylint: disable=too-many-locals
    global_configs = service_config.get_global_config()
    notifier_configs = service_config.get_notifier_config()

    if not inv_index_id:
        with service_config.scoped_session() as session:
            inv_index_id = (
                DataAccess.get_latest_inventory_index_id(session))

    # get violations
    violation_access_cls = scanner_dao.define_violation(
        service_config.engine)
    violation_access = violation_access_cls(service_config.engine)
    service_config.violation_access = violation_access
    violations = violation_access.list(inv_index_id)

    violations = convert_to_timestamp(violations)

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
    for resource in notifier_configs.get('resources', []):
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
            log_message = 'Running \'{}\' notifier for resource \'{}\''.format(
                notifier['name'], resource['resource'])
            progress_queue.put(log_message)
            LOGGER.info(log_message)
            chosen_pipeline = find_notifiers(notifier['name'])
            notifiers.append(chosen_pipeline(resource['resource'],
                                             inv_index_id,
                                             violations[resource['resource']],
                                             global_configs,
                                             notifier_configs,
                                             notifier['configuration']))

    # Run the notifiers.
    for notifier in notifiers:
        notifier.run()

    if (notifier_configs.get('violation') and
            notifier_configs.get('violation').get('findings').get('enabled')):
        findings.Findingsnotifier().run(
            violations_as_dict,
            notifier_configs.get('violation').get('findings').get('gcs_path'))

    inv_summary_notify(inv_index_id, service_config)
    log_message = 'Notification completed!'
    progress_queue.put(log_message)
    progress_queue.put(None)
    LOGGER.info(log_message)
    return 0
