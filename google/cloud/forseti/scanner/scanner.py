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
from google.cloud.forseti.scanner import scanner_builder
from google.cloud.forseti.services.scanner import dao as scanner_dao

LOGGER = logger.get_logger(__name__)


def init_scanner_index(service_config):
    """Initialize the 'scanner_index' table.

    Make sure we have a 'scanner_index' row for the current scanner run.

    Args:
        service_config (ServiceConfig): Forseti 2.0 service configs.

    Returns:
        str: the id of the 'scanner_index' db row
    """
    with service_config.scoped_session() as session:
        scanner_index = scanner_dao.ScannerIndex.create()
        session.add(scanner_index)
        session.flush()
        return scanner_index.id


def mark_scanner_index_complete(service_config):
    """Mark the current 'scanner_index' row as complete.

    Args:
        service_config (ServiceConfig): Forseti 2.0 service configs.
    """
    scanner_configs = service_config.get_scanner_config()
    scanner_index_id = scanner_configs['scanner_index_id']

    with service_config.scoped_session() as session:
        scanner_index = (
            session.query(scanner_dao.ScannerIndex)
            .filter(scanner_dao.ScannerIndex.id == scanner_index_id).one())
        scanner_index.complete()
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

    violation_access = scanner_dao.define_violation(service_config.engine)
    service_config.violation_access = violation_access

    scanner_configs['scanner_index_id'] = init_scanner_index(service_config)
    runnable_scanners = scanner_builder.ScannerBuilder(
        global_configs, scanner_configs, service_config, model_name,
        None).build()

    # pylint: disable=bare-except
    for scanner in runnable_scanners:
        try:
            scanner.run()
            progress_queue.put('Running {}...'.format(
                scanner.__class__.__name__))
        except:
            log_message = 'Error running scanner: {}'.format(
                scanner.__class__.__name__)
            progress_queue.put(log_message)
            LOGGER.error(log_message, exc_info=True)
    # pylint: enable=bare-except
    log_message = 'Scan completed!'
    mark_scanner_index_complete(service_config)
    progress_queue.put(log_message)
    progress_queue.put(None)
    LOGGER.info(log_message)
    return 0
