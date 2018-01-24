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
"""GCP Resource scanner.

Usage:

  Run scanner:
  $ forseti_scanner --forseti_config
"""

import gflags as flags

from google.apputils import app
from google.cloud.forseti.common.data_access import dao
from google.cloud.forseti.common.data_access import errors as db_errors
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import log_util
from google.cloud.forseti.scanner import scanner_builder
from google.cloud.forseti.services.scanner import dao as scanner_dao


# Setup flags
FLAGS = flags.FLAGS


# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# Example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py

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
SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


def _get_timestamp(global_configs, statuses=('SUCCESS', 'PARTIAL_SUCCESS')):
    """Get latest snapshot timestamp.

    Args:
        global_configs (dict): Global configurations.
        statuses (tuple): The snapshot statuses to search for latest timestamp.

    Returns:
        str: The latest snapshot timestamp.
    """
    latest_timestamp = None
    try:
        latest_timestamp = (
            dao.Dao(global_configs).get_latest_snapshot_timestamp(statuses))
    except db_errors.MySQLError as err:
        LOGGER.error('Error getting latest snapshot timestamp: %s', err)

    return latest_timestamp

def run(forseti_config, model_name=None, service_config=None):
    """Run the scanners.

    Entry point when the scanner is run as a library.

    Args:
        forseti_config (dict): Forseti 1.0 config
        model_name (str): name of the data model
        service_config (ServiceConfig): Forseti 2.0 service configs

    Returns:
        int: Status code.
    """

    if forseti_config is None:
        LOGGER.error('Path to Forseti Security config needs to be specified.')
        return 1

    try:
        configs = file_loader.read_and_parse_file(forseti_config)
    except IOError:
        LOGGER.error('Unable to open Forseti Security config file. '
                     'Please check your path and filename and try again.')
        return 1
    global_configs = configs.get('global')
    scanner_configs = configs.get('scanner')

    log_util.set_logger_level_from_config(scanner_configs.get('loglevel'))

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


def main(_):
    """Entry point when the scanner is run as an executable.

    Args:
        _ (list): args that aren't used

    Returns:
        int: Status code.
    """

    run(FLAGS.forseti_config)
    return 0


if __name__ == '__main__':
    app.run()
