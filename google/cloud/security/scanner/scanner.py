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
import sys

import gflags as flags

from google.apputils import app
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner import scanner_builder


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


def _get_previous_timestamp(global_configs):
    """Get previous snapshot timestamp.

    Args:
        global_configs (dict): Global configurations.

    Returns:
        str: The latest snapshot timestamp.
    """
    previous_timestamp = None
    try:
        previous_timestamp = (
            dao.Dao(global_configs).get_previous_snapshot_timestamp())
    except db_errors.MySQLError as err:
        LOGGER.error('Error getting latest snapshot timestamp: %s', err)

    return previous_timestamp

def _get_last_violations(global_configs):
    """Get last violations from previous timestamp.

    Args:
        global_configs (dict): Global configurations.

    Returns:
        old_violations (list):  A list of violations from previous timestamp
    """
    old_violations = []

    previous_timestamp = _get_previous_timestamp(global_configs)

    if not previous_timestamp:
        LOGGER.warn('No previous timestamp found.')
        return old_violations

    try:
        old_violations = violation_dao.ViolationDao(
                global_configs).get_all_violations(previous_timestamp)
    except db_errors.MySQLError as e:
        LOGGER.error('Error getting Violations: %s', e)

    return old_violations

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

def main(_):
    """Run the scanners.

    Args:
        _ (list): argv, unused due to apputils.
    """
    forseti_config = FLAGS.forseti_config
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
    scanner_configs = configs.get('scanner')

    log_util.set_logger_level_from_config(scanner_configs.get('loglevel'))

    snapshot_timestamp = _get_timestamp(global_configs)
    if not snapshot_timestamp:
        LOGGER.warn('No snapshot timestamp found. Exiting.')
        sys.exit()

    runnable_scanners = scanner_builder.ScannerBuilder(
        global_configs, scanner_configs, snapshot_timestamp).build()

    # get last violations for previous run
    last_violations = _get_last_violations(global_configs)

    # pylint: disable=bare-except
    for scanner in runnable_scanners:
        try:
            scanner.run(last_violations)
        except:
            LOGGER.error('Error running scanner: %s',
                         scanner.__class__.__name__, exc_info=True)
    # pylint: enable=bare-except

    LOGGER.info('Scan complete!')


if __name__ == '__main__':
    app.run()
