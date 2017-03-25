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

"""Organization resource scanner.

Usage:

  $ forseti_scanner --rules <rules path> \\
      --output_path <output path (optional)> \\
      --organization_id <organization_id> (required) \\
      --db_host <Cloud SQL database hostname/IP> \\
      --db_user <Cloud SQL database user> \\
      --db_passwd <Cloud SQL database password> \\
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
from google.cloud.security.common.data_access.dao import Dao
from google.cloud.security.common.data_access.errors import MySQLError
# pylint: disable=line-too-long
from google.cloud.security.common.gcp_type.resource import ResourceType
from google.cloud.security.common.gcp_type.resource_util import ResourceUtil
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.scanner.audit.org_rules_engine import OrgRulesEngine

# Setup flags
FLAGS = flags.FLAGS

# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# Example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py
flags.DEFINE_string('rules', None,
                    ('Path to rules file (yaml/json). '
                     'If GCS bucket, include full path, e.g. '
                     ' "gs://<bucketname>/path/to/file".'))

flags.DEFINE_string('output_path', None,
                    ('Output path (do not include filename). If GCS location, '
                     'the format of the path should be '
                     '"gs://bucket-name/path/for/output".'))

flags.DEFINE_string('organization_id', None, 'Organization id')

flags.mark_flag_as_required('rules')
flags.mark_flag_as_required('organization_id')

LOGGER = None

def main(_):
    """Run the scanner."""
    global LOGGER
    LOGGER = log_util.get_logger(__name__)
    LOGGER.info('Initializing the rules engine:\nUsing rules: %s', FLAGS.rules)

    rules_engine = OrgRulesEngine(rules_file_path=FLAGS.rules)
    rules_engine.build_rule_book()

    snapshot_timestamp = _get_timestamp()
    if not snapshot_timestamp:
        LOGGER.info('No snapshot timestamp found. Exiting.')
        sys.exit()

    org_policies = _get_org_policies(snapshot_timestamp)
    project_policies = _get_project_policies(snapshot_timestamp)

    if not org_policies and not project_policies:
        LOGGER.info('No policies found. Exiting.')
        sys.exit()

    all_violations = _find_violations(
        itertools.chain(
            org_policies.iteritems(),
            project_policies.iteritems()),
        rules_engine)

    # If there are violations, send results.
    if all_violations:
        resource_counts = {
            ResourceType.ORGANIZATION: len(org_policies),
            ResourceType.PROJECT: len(project_policies),
        }
        _output_results(all_violations, resource_counts=resource_counts)

    LOGGER.info('Done!')

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
        LOGGER.debug('{} => {}'.format(resource, policy))
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
    output_timestamp = now_utc.strftime('%Y%m%dT%H%M%SZ')
    output_filename = 'scanner_output.{}.csv'.format(output_timestamp)
    return output_filename

def _get_timestamp():
    """Get latest snapshot timestamp.

    Returns:
        The latest snapshot timestamp string.
    """
    dao = None
    latest_timestamp = None
    try:
        dao = Dao()
        latest_timestamp = dao.select_latest_complete_snapshot_timestamp(
            ('SUCCESS', 'PARTIAL_SUCCESS'))
    except MySQLError as err:
        LOGGER.error('Error getting latest snapshot timestamp: {}'.format(err))

    return latest_timestamp

def _get_org_policies(timestamp):
    """Get orgs from data source.

    Args:
        timestamp: The snapshot timestamp.

    Returns:
        The org policies.
    """
    from google.cloud.security.common.data_access.organization_dao \
        import OrganizationDao
    org_dao = None
    org_policies = {}
    try:
        org_dao = OrganizationDao()
        org_policies = org_dao.get_org_iam_policies(timestamp)
    except MySQLError as err:
        LOGGER.error('Error getting org policies: {}'.format(err))

    return org_policies

def _get_project_policies(timestamp):
    """Get projects from data source.

    Args:
        timestamp: The snapshot timestamp.

    Returns:
        The project policies.
    """
    from google.cloud.security.common.data_access.project_dao import ProjectDao
    project_dao = None
    project_policies = {}
    try:
        project_dao = ProjectDao()
        project_policies = project_dao.get_project_policies(timestamp)
    except MySQLError as err:
        LOGGER.error('Error getting project policies: {}'.format(err))

    return project_policies

def _write_violations_output(violations):
    """Write violations to csv output file and store in output bucket.

    Args:
        violations: The violations to write to the csv.
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

def _output_results(all_violations, **kwargs):
    """Send the output results.

    Args:
        all_violations: The list of violations to report.
        **kwargs: The rest of the args.
    """
    # Write the CSV.
    csv_name = csv_writer.write_csv(
        resource_name='policy_violations',
        data=_write_violations_output(all_violations),
        write_header=True)
    LOGGER.info('CSV filename: %s', csv_name)

    # Scanner timestamp for output file and email.
    now_utc = datetime.utcnow()

    # If output_path specified, upload to GCS.
    if FLAGS.output_path:
        _upload_csv_to_gcs(FLAGS.output_path, now_utc, csv_name)

    # Send summary email.
    if FLAGS.email_recipient is not None:
        resource_counts = kwargs.get('resource_counts', {})
        _send_email(csv_name, now_utc, all_violations, resource_counts)

def _upload_csv_to_gcs(output_path, now_utc, csv_name):
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
    LOGGER.info('Output filename: {}'.format(output_filename))

    if output_path.startswith('gs://'):
        # An output path for GCS must be the full
        # `gs://bucket-name/path/for/output`
        storage_client = storage.StorageClient()
        full_output_path = os.path.join(output_path, output_filename)

        storage_client.put_text_file(
            csv_name, full_output_path)
    else:
        # Otherwise, just copy it to the output path.
        shutil.copy(csv_name, os.path.join(output_path, output_filename))

def _send_email(csv_name, now_utc, all_violations, total_resources):
    """Send a summary email of the scan.

    Args:
        csv_name: The full path of the csv.
        now_utc: The UTC datetime right now.
        all_violations: The list of violations.
        total_resources: A dict of the resources and their count.
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
