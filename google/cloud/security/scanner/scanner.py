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
      --rules <rules path> \\
      --engine_name <rule engine name> \\
      --output_path <output path (optional)> \\
      --db_host <Cloud SQL database hostname/IP> \\
      --db_user <Cloud SQL database user> \\
      --db_name <Cloud SQL database name (required)> \\
      --sendgrid_api_key <API key to auth SendGrid email service> \\
      --email_sender <email address of the email sender> \\
      --email_recipient <email address of the email recipient>
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
flags.DEFINE_string('rules', None,
                    ('Path to rules file (yaml/json). '
                     'If GCS object, include full path, e.g. '
                     ' "gs://<bucketname>/path/to/file".'))

flags.DEFINE_string('output_path', None,
                    ('Output path (do not include filename). If GCS location, '
                     'the format of the path should be '
                     '"gs://bucket-name/path/for/output".'))

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

    snapshot_timestamp = _get_timestamp()
    if not snapshot_timestamp:
        LOGGER.warn('No snapshot timestamp found. Exiting.')
        sys.exit()

    # Load scanner from map
    scanner = sm.SCANNER_MAP[rules_engine_name](snapshot_timestamp)

    # The Groups Scanner uses a different approach to apply and
    # evaluate the rules.  Consolidate on next scanner design.
    if rules_engine_name == 'GroupsRulesEngine':
        all_violations = scanner.run(FLAGS.rules)
        resource_counts = None
    else:
        # Instantiate rules engine with supplied rules file
        rules_engine = em.ENGINE_TO_DATA_MAP[rules_engine_name](
            rules_file_path=FLAGS.rules, snapshot_timestamp=snapshot_timestamp)
        rules_engine.build_rule_book()

        iter_objects, resource_counts = scanner.run()

        # Load violations processing function
        all_violations = scanner.find_violations(
            itertools.chain(
                *iter_objects),
            rules_engine)

    # If there are violations, send results.
    flattening_scheme = sm.FLATTENING_MAP[rules_engine_name]
    if all_violations:
        _output_results(all_violations,
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

def _get_timestamp(statuses=('SUCCESS', 'PARTIAL_SUCCESS')):
    """Get latest snapshot timestamp.

    Args:
        statuses: The snapshot statuses to search for latest timestamp.

    Returns:
        The latest snapshot timestamp string.
    """

    latest_timestamp = None
    try:
        latest_timestamp = dao.Dao().get_latest_snapshot_timestamp(statuses)
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

    # TODO: Make this nicer
    LOGGER.info('Writing violations to csv...')
    for violation in violations:
        if flattening_scheme == 'policy_violations':
            for member in violation.members:
                yield {
                    'resource_id': violation.resource_id,
                    'resource_type': violation.resource_type,
                    'rule_index': violation.rule_index,
                    'rule_name': violation.rule_name,
                    'violation_type': violation.violation_type,
                    'role': violation.role,
                    'member': '{}:{}'.format(member.type, member.name)
                }
        if flattening_scheme == 'buckets_acl_violations':
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'role': violation.role,
                'entity': violation.entity,
                'email': violation.email,
                'domain': violation.domain,
                'bucket': violation.bucket,
            }
        if flattening_scheme == 'cloudsql_acl_violations':
            yield {
                'resource_id': violation.resource_id,
                'resource_type': violation.resource_type,
                'rule_index': violation.rule_index,
                'rule_name': violation.rule_name,
                'violation_type': violation.violation_type,
                'instance_name': violation.instance_name,
                'authorized_networks': violation.authorized_networks,
                'ssl_enabled': violation.ssl_enabled,
            }

def _output_results(all_violations, snapshot_timestamp, **kwargs):
    """Send the output results.

    Args:
        all_violations: The list of violations to report.
        snapshot_timestamp: The snapshot timetamp associated with this scan.
        **kwargs: The rest of the args.
    """

    # Write violations to database.
    flattening_scheme = kwargs.get('flattening_scheme')
    resource_name = sm.RESOURCE_MAP[flattening_scheme]
    (inserted_row_count, violation_errors) = (0, [])
    try:
        vdao = violation_dao.ViolationDao()
        (inserted_row_count, violation_errors) = vdao.insert_violations(
            all_violations, resource_name=resource_name,
            snapshot_timestamp=snapshot_timestamp)
    except db_errors.MySQLError as err:
        LOGGER.error('Error importing violations to database: %s', err)

    # TODO: figure out what to do with the errors. For now, just log it.
    LOGGER.debug('Inserted %s rows with %s errors',
                 inserted_row_count, len(violation_errors))

    # Write the CSV for all the violations.
    if FLAGS.output_path:
        output_csv_name = None
        with csv_writer.write_csv(
            resource_name=flattening_scheme,
            data=_flatten_violations(all_violations,
                                     flattening_scheme),
            write_header=True) as csv_file:
            output_csv_name = csv_file.name
            LOGGER.info('CSV filename: %s', output_csv_name)

            # Scanner timestamp for output file and email.
            now_utc = datetime.utcnow()

            output_path = FLAGS.output_path
            if not output_path.startswith('gs://'):
                if not os.path.exists(FLAGS.output_path):
                    os.makedirs(output_path)
                output_path = os.path.abspath(output_path)
            _upload_csv(output_path, now_utc, output_csv_name)

            # Send summary email.
            if FLAGS.email_recipient is not None:
                payload = {
                    'email_sender': FLAGS.email_sender,
                    'email_recipient': FLAGS.email_recipient,
                    'sendgrid_api_key': FLAGS.sendgrid_api_key,
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
