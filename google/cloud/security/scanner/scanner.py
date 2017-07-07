# Copyright 2017 Google Inc.
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

  List rules engines:
  $ forseti_scanner --list_engines

  Run scanner:
  $ forseti_scanner \\
      --forseti_config (optional) \\
      --rules <rules path> \\
      --engine_name <rule engine name>
"""
import sys

import gflags as flags

from google.apputils import app
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import engine_map as em
from google.cloud.security.scanner.scanners import iam_rules_scanner


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc
# pylint: disable=missing-param-doc,redundant-returns-doc
# pylint: disable=differing-param-doc,missing-yield-type-doc


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

flags.DEFINE_string('rules', None,
                    ('Path to rules file (yaml/json). '
                     'If GCS object, include full path, e.g. '
                     ' "gs://<bucketname>/path/to/file".'))

flags.DEFINE_boolean('list_engines', False, 'List all rule engines')

flags.DEFINE_string('engine_name', None, 'Which engine to use')

LOGGER = log_util.get_logger(__name__)
SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


def _get_runnable_scanners(global_configs, scanner_configs, snapshot_timestamp):
        # Load scanner from map
    scanner = iam_rules_scanner.IamPolicyScanner(
        global_configs,
        scanner_configs,
        snapshot_timestamp,
        FLAGS.rules)
    return [scanner]

def _list_rules_engines():
    """List rules engines.

    Args:
        audit_base_dir: base directory for rules engines

    Returns:
        None
    """
    for engine in em.ENGINE_TO_DATA_MAP:
        print engine

def _get_timestamp(global_configs, statuses=('SUCCESS', 'PARTIAL_SUCCESS')):
    """Get latest snapshot timestamp.

    Args:
        global_configs (dict): Global configurations.
        statuses (tuple): The snapshot statuses to search for latest timestamp.

    Returns:
        The latest snapshot timestamp string.
    """

    latest_timestamp = None
    try:
        latest_timestamp = (
            dao.Dao(global_configs).get_latest_snapshot_timestamp(statuses))
    except db_errors.MySQLError as err:
        LOGGER.error('Error getting latest snapshot timestamp: %s', err)

    return latest_timestamp

def main(_):
    """Run the scanner."""
    if FLAGS.list_engines is True:
        _list_rules_engines()
        sys.exit(1)

    if not FLAGS.engine_name:
        LOGGER.warn('Provide an engine name')
        sys.exit(1)
    else:
        rules_engine_name = FLAGS.engine_name

    LOGGER.info('Using rules engine: %s', rules_engine_name)

    LOGGER.info('Initializing the rules engine:\nUsing rules: %s', FLAGS.rules)

    if not FLAGS.rules:
        LOGGER.warn(('Provide a rules file. '
                     'Use "forseti_scanner --helpfull" for help.'))
        sys.exit(1)

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

    snapshot_timestamp = _get_timestamp(global_configs)
    if not snapshot_timestamp:
        LOGGER.warn('No snapshot timestamp found. Exiting.')
        sys.exit()

    runnable_scanners = _get_runnable_scanners(
        global_configs, scanner_configs, snapshot_timestamp)

    for scanner in runnable_scanners:
        scanner.run()

    LOGGER.info('Scan complete!')


if __name__ == '__main__':
    app.run()
