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
"""GCP Resource scanner."""

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.index_state import IndexState
from google.cloud.forseti.scanner import scanner_builder
from google.cloud.forseti.services.scanner import dao as scanner_dao

LOGGER = logger.get_logger(__name__)


def init_scanner_index(session, inventory_index_id):
    """Initialize the 'scanner_index' table.

    Make sure we have a 'scanner_index' row for the current scanner run.

    Args:
        session (Session): SQLAlchemy session object.
        inventory_index_id (str): Id of the inventory index.

    Returns:
        str: the id of the 'scanner_index' db row
    """
    scanner_index = scanner_dao.ScannerIndex.create(inventory_index_id)
    scanner_index.scanner_status = IndexState.RUNNING
    session.add(scanner_index)
    session.flush()
    return scanner_index.id


def _error_message(failed):
    """Construct error message for failed scanners.

    Args:
        failed (list): names of scanners that failed

    Returns:
        str: error message detailing the scanners that failed
    """
    return 'Scanner(s) with errors: %s' % ', '.join(failed)


def mark_scanner_index_complete(
        session, scanner_index_id, succeeded, failed):
    """Mark the current 'scanner_index' row as complete.

    Args:
        session (Session): SQLAlchemy session object.
        scanner_index_id (str): id of the `ScannerIndex` row to mark
        succeeded (list): names of scanners that ran successfully
        failed (list): names of scanners that failed
    """
    scanner_index = (
        session.query(scanner_dao.ScannerIndex)
        .filter(scanner_dao.ScannerIndex.id == scanner_index_id).one())
    if failed and succeeded:
        scanner_index.complete(IndexState.PARTIAL_SUCCESS)
    elif not failed:
        scanner_index.complete(IndexState.SUCCESS)
    else:
        scanner_index.complete(IndexState.FAILURE)
    if failed:
        scanner_index.set_error(session, _error_message(failed))
    session.add(scanner_index)
    session.flush()


def run(model_name=None, progress_queue=None, service_config=None):
    """Run the scanners.

    Entry point when the scanner is run as a library.

    Args:
        model_name (str): The name of the data model.
        progress_queue (Queue): The progress queue.
        service_config (ServiceConfig): Forseti 2.0 service configs.

    Returns:
        int: Status code.
    """
    global_configs = service_config.get_global_config()
    scanner_configs = service_config.get_scanner_config()

    with service_config.scoped_session() as session:
        service_config.violation_access = scanner_dao.ViolationAccess(session)
        model_description = (
            service_config.model_manager.get_description(model_name))
        inventory_index_id = (
            model_description.get('source_info').get('inventory_index_id'))
        scanner_index_id = init_scanner_index(session, inventory_index_id)
        runnable_scanners = scanner_builder.ScannerBuilder(
            global_configs, scanner_configs, service_config, model_name,
            None).build()

        succeeded = []
        failed = []
        for scanner in runnable_scanners:
            try:
                scanner.run()
                progress_queue.put('Running {}...'.format(
                    scanner.__class__.__name__))
            except Exception:  # pylint: disable=broad-except
                log_message = 'Error running scanner: {}'.format(
                    scanner.__class__.__name__)
                progress_queue.put(log_message)
                LOGGER.exception(log_message)
                failed.append(scanner.__class__.__name__)
            else:
                succeeded.append(scanner.__class__.__name__)
            session.flush()
        # pylint: enable=bare-except
        log_message = 'Scan completed!'
        mark_scanner_index_complete(
            session, scanner_index_id, succeeded, failed)
        progress_queue.put(log_message)
        progress_queue.put(None)
        LOGGER.info(log_message)
        return 0
