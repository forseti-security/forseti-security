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


import itertools
import os
import shutil
import sys

from datetime import datetime
import gflags as flags

from google.apputils import app
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util
from google.cloud.security.scanner.audit import engine_map as em
from google.cloud.security.scanner.scanners import scanners_map as sm
from google.cloud.security.notifier import notifier


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
    configs = file_loader.read_and_parse_file(forseti_config)
    global_configs = configs.get('global')
    scanner_configs = configs.get('scanner')

    snapshot_timestamp = _get_timestamp(global_configs)
    if not snapshot_timestamp:
        LOGGER.warn('No snapshot timestamp found. Exiting.')
        sys.exit()

    # Load scanner from map
    scanner = sm.SCANNER_MAP[rules_engine_name](global_configs,
                                                snapshot_timestamp)

    # The Groups Scanner uses a different approach to apply and
    # evaluate the rules.  Consolidate on next scanner design.
    if rules_engine_name == 'GroupsRulesEngine':
        all_violations = scanner.run(FLAGS.rules)
        resource_counts = None
    else:
        # Instantiate rules engine with supplied rules file
        rules_engine = em.ENGINE_TO_DATA_MAP[rules_engine_name](
            rules_file_path=FLAGS.rules, snapshot_timestamp=snapshot_timestamp)
        rules_engine.build_rule_book(global_configs)

        iter_objects, resource_counts = scanner.run()

        # Load violations processing function
        all_violations = scanner.find_violations(
            itertools.chain(
                *iter_objects),
            rules_engine)

    # If there are violations, send results.
    flattening_scheme = sm.FLATTENING_MAP[rules_engine_name]
    if all_violations:
        _output_results(global_configs,
                        scanner_configs,
                        all_violations,
                        snapshot_timestamp,
                        resource_counts=resource_counts,
                        flattening_scheme=flattening_scheme)

    LOGGER.info('Scan complete!')

def _list_rules_engines():
    """List rules engines.

    Args:
        audit_base_dir: base directory for rules engines

    Returns:
        None
    """
    for engine in em.ENGINE_TO_DATA_MAP:
        print engine

def _get_output_filename(now_utc):
    """Create the output filename.

    Args:
        now_utc: The datetime now in UTC. Generated at the top level to be
            consistent across the scan.

    Returns:
        The output filename for the csv, formatted with the now_utc timestamp.
    """

    output_timestamp = now_utc.strftime(OUTPUT_TIMESTAMP_FMT)
    output_filename = SCANNER_OUTPUT_CSV_FMT.format(output_timestamp)
    return output_filename

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

def _flatten_violations(violations, flattening_scheme):
    """Flatten RuleViolations into a dict for each RuleViolation member.

    Args:
        violations: The RuleViolations to flatten.
        flattening_scheme: Which flattening scheme to use

    Yield:
        Iterator of RuleViolations as a dict per member.
    """
    # TODO: Write custom flattening methods for each violation type.
    for violation in violations:
        if flattening_scheme == 'policy_violations':
            for member in violation.members:
                violation_data = {}
                violation_data['role'] = violation.role
                violation_data['member'] = '%s:%s' % (member.type, member.name)

                yield {
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'violation_data': violation_data
                }
        if flattening_scheme == 'buckets_acl_violations':
            violation_data = {}
            violation_data['role'] = violation.role
            violation_data['entity'] = violation.entity
            violation_data['email'] = violation.email
            violation_data['domain'] = violation.domain
            violation_data['bucket'] = violation.bucket
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }
        if flattening_scheme == 'cloudsql_acl_violations':
            violation_data = {}
            violation_data['instance_name'] = violation.instance_name
            violation_data['authorized_networks'] =\
                                                  violation.authorized_networks
            violation_data['ssl_enabled'] = violation.ssl_enabled
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }
        if flattening_scheme == 'bigquery_acl_violations':
            violation_data = {}
            violation_data['dataset_id'] = violation.dataset_id
            violation_data['access_domain'] = violation.domain
            violation_data['access_user_by_email'] = violation.user_email
            violation_data['access_special_group'] = violation.special_group
            violation_data['access_group_by_email'] = violation.group_email
            violation_data['role'] = violation.role
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'violation_data': violation_data
            }
        if flattening_scheme == 'instance_network_interface_violations':
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'project': violation.project,
                'network': violation.network,
                'ip': violation.ip,
            }

def _output_results(global_configs, scanner_configs, all_violations,
                    snapshot_timestamp, **kwargs):
    """Send the output results.

    Args:
        all_violations: The list of violations to report.
        snapshot_timestamp: The snapshot timetamp associated with this scan.
        **kwargs: The rest of the args.
    """
    # pylint: disable=too-many-locals
    # Write violations to database.
    flattening_scheme = kwargs.get('flattening_scheme')
    resource_name = sm.RESOURCE_MAP[flattening_scheme]
    (inserted_row_count, violation_errors) = (0, [])
    all_violations = _flatten_violations(all_violations, flattening_scheme)
    try:
        vdao = violation_dao.ViolationDao(global_configs)
        (inserted_row_count, violation_errors) = vdao.insert_violations(
            all_violations,
            resource_name=resource_name,
            snapshot_timestamp=snapshot_timestamp)
    except db_errors.MySQLError as err:
        LOGGER.error('Error importing violations to database: %s', err)

    # TODO: figure out what to do with the errors. For now, just log it.
    LOGGER.debug('Inserted %s rows with %s errors',
                 inserted_row_count, len(violation_errors))

    # TODO: Remove this specific return when tying the scanner to the general
    # violations table.
    if resource_name != 'violations':
        return

    # Write the CSV for all the violations.
    if scanner_configs.get('output_path'):
        LOGGER.info('Writing violations to csv...')
        output_csv_name = None
        with csv_writer.write_csv(
            resource_name=resource_name,
            data=all_violations,
            write_header=True) as csv_file:
            output_csv_name = csv_file.name
            LOGGER.info('CSV filename: %s', output_csv_name)

            # Scanner timestamp for output file and email.
            now_utc = datetime.utcnow()

            output_path = scanner_configs.get('output_path')
            if not output_path.startswith('gs://'):
                if not os.path.exists(scanner_configs.get('output_path')):
                    os.makedirs(output_path)
                output_path = os.path.abspath(output_path)
            _upload_csv(output_path, now_utc, output_csv_name)

            # Send summary email.
            if global_configs.get('email_recipient') is not None:
                payload = {
                    'email_sender': global_configs.get('email_sender'),
                    'email_recipient': global_configs.get('email_recipient'),
                    'sendgrid_api_key': global_configs.get('sendgrid_api_key'),
                    'output_csv_name': output_csv_name,
                    'output_filename': _get_output_filename(now_utc),
                    'now_utc': now_utc,
                    'all_violations': all_violations,
                    'resource_counts': kwargs.get('resource_counts', {}),
                    'violation_errors': violation_errors
                }
                message = {
                    'status': 'scanner_done',
                    'payload': payload
                }
                notifier.process(message)
    # pylint: enable=too-many-locals

def _upload_csv(output_path, now_utc, csv_name):
    """Upload CSV to Cloud Storage.

    Args:
        output_path: The output path for the csv.
        now_utc: The UTC timestamp of "now".
        csv_name: The csv_name.
    """

    from google.cloud.security.common.gcp_api import storage

    output_filename = _get_output_filename(now_utc)

    # If output path was specified, copy the csv temp file either to
    # a local file or upload it to Google Cloud Storage.
    full_output_path = os.path.join(output_path, output_filename)
    LOGGER.info('Output path: %s', full_output_path)

    if output_path.startswith('gs://'):
        # An output path for GCS must be the full
        # `gs://bucket-name/path/for/output`
        storage_client = storage.StorageClient()
        storage_client.put_text_file(
            csv_name, full_output_path)
    else:
        # Otherwise, just copy it to the output path.
        shutil.copy(csv_name, full_output_path)


if __name__ == '__main__':
    app.run()
