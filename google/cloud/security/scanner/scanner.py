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

  $ forseti_scanner --rules <rules path> \\
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
import glob
import ast
import imp

from datetime import datetime

import gflags as flags

from google.apputils import app
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.scanner.audit.iam_rules_engine import IamRulesEngine

# Setup flags
FLAGS = flags.FLAGS

# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# Example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py
flags.DEFINE_string('rules', None,
                    ('Path to rules file (yaml/json). '
                     'If GCS object, include full path, e.g. '
                     ' "gs://<bucketname>/path/to/file".'))

flags.DEFINE_string('group_rules', None,
                    ('Path to rules file (yaml/json). '
                     'If GCS object, include full path, e.g. '
                     ' "gs://<bucketname>/path/to/file".'))

flags.DEFINE_string('output_path', None,
                    ('Output path (do not include filename). If GCS location, '
                     'the format of the path should be '
                     '"gs://bucket-name/path/for/output".'))

flags.DEFINE_bool('list_engines', False, 'List all rule engines')

flags.DEFINE_string('use_engine', None, 'Which engine to use')

LOGGER = log_util.get_logger(__name__)
SCANNER_OUTPUT_CSV_FMT = 'scanner_output.{}.csv'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


def main(_):
    """Run the scanner."""
    audit_base_dir = os.path.dirname(__file__) + '/audit/'

    if FLAGS.list_engines:
        glob_string = audit_base_dir + '*engine*.py'
        engines = glob.glob(glob_string)
        print 'Available Forseti scanner engines:'
        for engine in engines:
            if 'base_rules_engine.py' not in engine:
                print os.path.basename(engine)
        sys.exit(1)

    if not FLAGS.use_engine:
        LOGGER.warn('Provide an engine file')
        sys.exit(1)
    else:
        rules_engine_filename = FLAGS.use_engine

    rules_engine_class = _create_rules_engine(audit_base_dir,
                                              rules_engine_filename)

    LOGGER.info('Using rules engine: %s', rules_engine_filename)

    LOGGER.info('Initializing the rules engine:\nUsing rules: %s', FLAGS.rules)

    if not FLAGS.rules:
        LOGGER.warn(('Provide a rules file. '
                     'Use "forseti_scanner --helpfull" for help.'))
        sys.exit(1)

    rules_engine = rules_engine_class(rules_file_path=FLAGS.rules)
    rules_engine.build_rule_book()

    snapshot_timestamp = _get_timestamp()
    if not snapshot_timestamp:
        LOGGER.warn('No snapshot timestamp found. Exiting.')
        sys.exit()

    # TODO: make this generic
    j = []
    org_policies = _get_org_policies(snapshot_timestamp)
    project_policies = _get_project_policies(snapshot_timestamp)
    j.append(org_policies.iteritems())
    j.append(project_policies.iteritems())
    if not org_policies and not project_policies:
        LOGGER.warn('No policies found. Exiting.')
        sys.exit()

    all_violations = _find_violations(
        itertools.chain(
            *j),
        rules_engine)

    #all_violations = _find_violations(
    #    itertools.chain(
    #        org_policies.iteritems(),
    #        project_policies.iteritems()),
    #    rules_engine)

    # If there are violations, send results.
    if all_violations:
        resource_counts = {
            ResourceType.ORGANIZATION: len(org_policies),
            ResourceType.PROJECT: len(project_policies),
        }
        _output_results(all_violations,
                        snapshot_timestamp,
                        resource_counts=resource_counts)

    LOGGER.info('Done!')

def _import_rules_engine(path, name):
    """Load rules engine

    Args:
        path: System path of module.
        name: Name of the file.

    Returns:
        Module.
    """
    name, ext = os.path.splitext(name)
    try:
        file_location, filename, data = imp.find_module(name, [path])
        module = imp.load_module(name, file_location, filename, data)
    except ImportError as err:
        LOGGER.error('Failed to import module %s', name)
    return module

def _create_rules_engine(audit_base_dir, rules_engine_filename):
    """Create the rules engine class

    Args:
        audit_base_dir: Base directory with enignes.
        rules_engine_filename: Rules engine python file.

    Returns:
        Rules engined class.
    """
    rules_engine_class_name = None

    try:
        class_file = open(audit_base_dir + rules_engine_filename)
    except IOError as err:
        LOGGER.error('Error opening module file: %s', err)
        sys.exit(1)

    module_tree = ast.parse(class_file.read())
    for node in ast.walk(module_tree):
        if isinstance(node, ast.ClassDef) and 'Engine' in node.name:
            rules_engine_class_name = node.name

    if rules_engine_class_name is None:
        LOGGER.error('Engine module %s wasn\'t loaded', rules_engine_filename)
        sys.exit(1)

    rules_engine_module = _import_rules_engine(audit_base_dir,
                                               rules_engine_filename)
    rules_engine_class = getattr(rules_engine_module, rules_engine_class_name)

    return rules_engine_class

def _find_violations(policies, rules_engine):
    """Find violations in the policies.

    Args:
        policies: The list of policies to find violations in.
        rules_engine: The rules engine to run.

    Returns:
        A list of violations.
    """

    all_violations = []
    LOGGER.info('Finding policy violations...')
    for (resource, policy) in policies:
        LOGGER.debug('%s => %s', resource, policy)
        violations = rules_engine.find_policy_violations(
            resource, policy)
        LOGGER.debug(violations)
        all_violations.extend(violations)
    return all_violations

def _get_output_filename(now_utc):
    """Create the output filename.

    Args:
        now_utc: The datetime now in UTC.

    Returns:
        The output filename for the csv, formatted with the now_utc timestamp.
    """

    output_timestamp = now_utc.strftime(OUTPUT_TIMESTAMP_FMT)
    output_filename = SCANNER_OUTPUT_CSV_FMT.format(output_timestamp)
    return output_filename

def _get_timestamp(statuses=('SUCCESS', 'PARTIAL_SUCCESS')):
    """Get latest snapshot timestamp.

    Returns:
        The latest snapshot timestamp string.
    """

    latest_timestamp = None
    try:
        latest_timestamp = dao.Dao().get_latest_snapshot_timestamp(statuses)
    except db_errors.MySQLError as err:
        LOGGER.error('Error getting latest snapshot timestamp: %s', err)

    return latest_timestamp

def _get_org_policies(timestamp):
    """Get orgs from data source.

    Args:
        timestamp: The snapshot timestamp.

    Returns:
        The org policies.
    """

    org_policies = {}
    org_dao = organization_dao.OrganizationDao()
    org_policies = org_dao.get_org_iam_policies('organizations', timestamp)
    return org_policies

def _get_project_policies(timestamp):
    """Get projects from data source.

    Args:
        timestamp: The snapshot timestamp.

    Returns:
        The project policies.
    """

    project_policies = {}
    project_policies = (
        project_dao.ProjectDao().get_project_policies('projects', timestamp))
    return project_policies

def _flatten_violations(violations):
    """Flatten RuleViolations into a dict for each RuleViolation member.

    Args:
        violations: The RuleViolations to flatten.

    Yield:
        Iterator of RuleViolations as a dict per member.
    """

    LOGGER.info('Writing violations to csv...')
    for violation in violations:
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

def _output_results(all_violations, snapshot_timestamp, **kwargs):
    """Send the output results.

    Args:
        all_violations: The list of violations to report.
        **kwargs: The rest of the args.
    """

    # Write violations to database.
    (inserted_row_count, violation_errors) = (0, [])
    try:
        vdao = violation_dao.ViolationDao()
        (inserted_row_count, violation_errors) = vdao.insert_violations(
            all_violations, snapshot_timestamp=snapshot_timestamp)
    except db_errors.MySQLError as err:
        LOGGER.error('Error importing violations to database: %s', err)

    # TODO: figure out what to do with the errors. For now, just log it.
    LOGGER.debug('Inserted %s rows with %s errors',
                 inserted_row_count, len(violation_errors))

    output_csv_name = None

    # Write the CSV for all the violations.
    with csv_writer.write_csv(
        resource_name='policy_violations',
        data=_flatten_violations(all_violations),
        write_header=True) as csv_file:
        output_csv_name = csv_file.name
        LOGGER.info('CSV filename: %s', output_csv_name)

        # Scanner timestamp for output file and email.
        now_utc = datetime.utcnow()

        # If output_path specified, upload to GCS.
        if FLAGS.output_path:
            output_path = FLAGS.output_path
            if not output_path.startswith('gs://'):
                if not os.path.exists(FLAGS.output_path):
                    os.makedirs(output_path)
                output_path = os.path.abspath(output_path)
            _upload_csv(output_path, now_utc, output_csv_name)

        # Send summary email.
        if FLAGS.email_recipient is not None:
            resource_counts = kwargs.get('resource_counts', {})
            _send_email(output_csv_name, now_utc,
                        all_violations, resource_counts,
                        violation_errors)

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

def _send_email(csv_name, now_utc, all_violations,
                total_resources, violation_errors):
    """Send a summary email of the scan.

    Args:
        csv_name: The full path of the csv.
        now_utc: The UTC datetime right now.
        all_violations: The list of violations.
        total_resources: A dict of the resources and their count.
        violation_errors: Iterable of violation errors.
    """

    mail_util = EmailUtil(FLAGS.sendgrid_api_key)
    total_violations, resource_summaries = _build_scan_summary(
        all_violations, total_resources)

    # Render the email template with values.
    scan_date = now_utc.strftime('%Y %b %d, %H:%M:%S (UTC)')
    email_content = EmailUtil.render_from_template(
        'scanner_summary.jinja', {
            'scan_date':  scan_date,
            'resource_summaries': resource_summaries,
            'violation_errors': violation_errors,
        })

    # Create an attachment out of the csv file and base64 encode the content.
    attachment = EmailUtil.create_attachment(
        file_location=csv_name,
        content_type='text/csv',
        filename=_get_output_filename(now_utc),
        disposition='attachment',
        content_id='Scanner Violations'
    )
    scanner_subject = 'Policy Scan Complete - {} violations found'.format(
        total_violations)
    mail_util.send(email_sender=FLAGS.email_sender,
                   email_recipient=FLAGS.email_recipient,
                   email_subject=scanner_subject,
                   email_content=email_content,
                   content_type='text/html',
                   attachment=attachment)

def _build_scan_summary(all_violations, total_resources):
    """Build the scan summary.

    Args:
        all_violations: List of violations.
        total_resources: A dict of the resources and their count.

    Returns:
        Total counts and summaries.
    """

    resource_summaries = {}
    total_violations = 0
    # Build a summary of the violations and counts for the email.
    # resource summary:
    # {
    #     RESOURCE_TYPE: {
    #         'total': TOTAL,
    #         'ids': [...] # resource_ids
    #     },
    #     ...
    # }
    for violation in all_violations:
        resource_type = violation.resource_type
        if resource_type not in resource_summaries:
            resource_summaries[resource_type] = {
                'pluralized_resource_type': ResourceUtil.pluralize(
                    resource_type),
                'total': total_resources[resource_type],
                'violations': {}
            }

        # Keep track of # of violations per resource id.
        if (violation.resource_id not in
                resource_summaries[resource_type]['violations']):
            resource_summaries[resource_type][
                'violations'][violation.resource_id] = 0

        resource_summaries[resource_type][
            'violations'][violation.resource_id] += len(violation.members)
        total_violations += len(violation.members)

    return total_violations, resource_summaries


if __name__ == '__main__':
    app.run()
