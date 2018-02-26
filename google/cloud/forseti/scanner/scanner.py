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

SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


def run(model_name=None, service_config=None):
    """Run the scanners.

    Entry point when the scanner is run as a library.

    Args:
        model_name (str): name of the data model
        service_config (ServiceConfig): Forseti 2.0 service configs

    Returns:
        int: Status code.
    """

    global_configs = service_config.get_global_config()
    scanner_configs = service_config.get_scanner_config()

    # TODO: Figure out if we still need to get the latest model here,
    # or should it be set in the server context before calling the scanner.
    #snapshot_timestamp = _get_timestamp(global_configs)
    #if not snapshot_timestamp:
    #    LOGGER.warn('No snapshot timestamp found. Exiting.')
    #    sys.exit()

    violation_access = scanner_dao.define_violation(service_config.engine)
    service_config.violation_access = violation_access

    runnable_scanners = scanner_builder.ScannerBuilder(
        global_configs, scanner_configs, service_config, model_name,
        None).build()

    # pylint: disable=bare-except
    for scanner in runnable_scanners:
        try:
            scanner.run()
        except:
            LOGGER.error('Error running scanner: %s',
                         scanner.__class__.__name__, exc_info=True)
    # pylint: enable=bare-except

    LOGGER.info('Scan complete!')
    return 0
