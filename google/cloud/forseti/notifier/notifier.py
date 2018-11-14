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
"""Notifier runner."""

import importlib
import inspect

# pylint: disable=line-too-long
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers.base_notification import BaseNotification
from google.cloud.forseti.notifier.notifiers import cscc_notifier
from google.cloud.forseti.notifier.notifiers.inventory_summary import InventorySummary
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
    except ImportError:
        LOGGER.exception('Can\'t import notifier %s', notifier_name)

# pylint: enable=inconsistent-return-statements


def convert_to_timestamp(violations):
    """Convert violation created_at_datetime to timestamp string.

    Args:
        violations (dict): List of violations as dict with
            created_at_datetime.

    Returns:
        list: List of violations as dict with created_at_datetime
            converted to timestamp string.
    """
    for violation in violations:
        violation['created_at_datetime'] = (
            violation['created_at_datetime'].strftime(
                string_formats.TIMESTAMP_TIMEZONE))

    return violations


# pylint: disable=too-many-branches,too-many-statements
def run(inventory_index_id, progress_queue, service_config=None):
    """Run the notifier.

    Entry point when the notifier is run as a library.

    Args:
        inventory_index_id (int64): Inventory index id.
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
        scanner_index_id = scanner_dao.get_latest_scanner_index_id(
            session, inventory_index_id)
        if not scanner_index_id:
            LOGGER.error(
                'No success or partial success scanner index found for '
                'inventory index: "%s".', str(inventory_index_id))
        else:
            # get violations
            violation_access = scanner_dao.ViolationAccess(session)
            violations = violation_access.list(
                scanner_index_id=scanner_index_id)
            violations_as_dict = []
            for violation in violations:
                violations_as_dict.append(
                    scanner_dao.convert_sqlalchemy_object_to_dict(violation))
            violations_as_dict = convert_to_timestamp(violations_as_dict)
            violation_map = scanner_dao.map_by_resource(violations_as_dict)

            for retrieved_v in violation_map:
                log_message = (
                    'Retrieved {} violations for resource \'{}\''.format(
                        len(violation_map[retrieved_v]), retrieved_v))
                LOGGER.info(log_message)
                progress_queue.put(log_message)

            # build notification notifiers
            notifiers = []
            for resource in notifier_configs['resources']:
                if violation_map.get(resource['resource']) is None:
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
                        violation_map[resource['resource']], global_configs,
                        notifier_configs, notifier['configuration']))

            # Run the notifiers.
            for notifier in notifiers:
                notifier.run()

            # Run the CSCC notifier.
            violation_configs = notifier_configs.get('violation')
            if violation_configs:
                if violation_configs.get('cscc').get('enabled'):
                    source_id = violation_configs.get('cscc').get('source_id')
                    if source_id:
                        # beta mode
                        LOGGER.debug(
                            'Running CSCC notifier with beta API. source_id: '
                            '%s', source_id)
                        (cscc_notifier.CsccNotifier(inventory_index_id)
                         .run(violations_as_dict, source_id=source_id))
                    else:
                        # alpha mode
                        LOGGER.debug('Running CSCC notifier with alpha API.')
                        gcs_path = (
                            violation_configs.get('cscc').get('gcs_path'))
                        mode = violation_configs.get('cscc').get('mode')
                        organization_id = (
                            violation_configs.get('cscc').get(
                                'organization_id'))
                        (cscc_notifier.CsccNotifier(inventory_index_id)
                         .run(violations_as_dict, gcs_path, mode,
                              organization_id))

        InventorySummary(service_config, inventory_index_id).run()

        log_message = 'Notification completed!'
        progress_queue.put(log_message)
        progress_queue.put(None)
        LOGGER.info(log_message)
        return 0
    # pylint: enable=too-many-branches,too-many-statements
