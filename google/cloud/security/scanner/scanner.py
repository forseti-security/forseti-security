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
      --output_path <output path (opt)> \\
      --db_host <Cloud SQL hostname/IP> \\
      --db_user <Cloud SQL user> \\
      --db_passwd <Cloud SQL password> \\
      --db_name <Cloud SQL database name> \\
      --organization_id <Organization id>
"""

import csv
import gflags as flags
import os
import shutil
import sys
import tempfile

from datetime import datetime

from google.apputils import app
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access.dao import Dao
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.organization_dao import OrganizationDao
from google.cloud.security.common.data_access.project_dao import ProjectDao
from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.scanner.audit.org_rules_engine import OrgRulesEngine

# Setup flags
FLAGS = flags.FLAGS

# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py
flags.DEFINE_string('rules',
                    None,
                    ('Path to rules file (yaml/json). '
                     'If GCS bucket, include full path, e.g. '
                     ' "gs://<bucketname>/path/to/file".'))
flags.DEFINE_string('output_path',
                    None,
                    ('Output path (do not include filename). If GCS location, '
                     'the format of the path should be '
                     '"gs://bucket-name/path/for/output".'))
flags.DEFINE_string('organization_id', None, 'Organization id')
flags.mark_flag_as_required('rules')
flags.mark_flag_as_required('organization_id')

def main(unused_argv=None):
    """Run the scanner."""
    logger = LogUtil.setup_logging(__name__)

    file_path = FLAGS.rules
    output_path = FLAGS.output_path

    logger.info(('Initializing the rules engine: '
                 '\n    rules: {}').format(file_path))

    rules_engine = OrgRulesEngine(rules_file_path=file_path)
    rules_engine.build_rule_book()

    snapshot_timestamp = _get_timestamp(logger)
    if not snapshot_timestamp:
        logger.info('No snapshot timestamp found. Exiting.')
        sys.exit()

    org_policies = _get_org_policies(logger, snapshot_timestamp)
    project_policies = _get_project_policies(logger, snapshot_timestamp)
    if not org_policies and not project_policies:
        logger.info('No policies found. Exiting.')
        sys.exit()

    all_violations = []

    logger.info('Find org policy violations...')
    for (org, policy) in org_policies.iteritems():
        logger.debug('{} => {}'.format(org, policy))
        org_violations = rules_engine.find_policy_violations(
            org, policy)
        logger.debug(org_violations)
        all_violations.extend(org_violations)

    logger.info('Find project policy violations...')
    for (project, policy) in project_policies.iteritems():
        logger.debug('{} => {}'.format(project, policy))
        project_violations = rules_engine.find_policy_violations(
            project, policy)
        logger.debug(project_violations)
        all_violations.extend(project_violations)

    csv_name = csv_writer.write_csv(
        resource_name='policy_violations',
        data=_write_violations_output(logger, all_violations),
        write_header=True)
    logger.info('CSV filename: {}'.format(csv_name))

    # If output path was specified, copy the csv temp file either to
    # a local file or upload it to Google Cloud Storage.
    if output_path:
        output_filename = _get_output_filename()
        logger.info('Output filename: {}'.format(output_filename))

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

    logger.info('Done!')

def _get_output_filename():
    """Create the output filename."""
    now_utc = datetime.utcnow()
    output_timestamp = now_utc.strftime('%Y%m%dT%H%M%SZ')
    output_filename = 'scanner_output.{}.csv'.format(output_timestamp)
    return output_filename

def _get_timestamp(logger):
    """Get latest snapshot timestamp."""
    dao = None
    latest_timestamp = None
    try:
        dao = Dao()
        latest_timestamp = dao.select_latest_complete_snapshot_timestamp(
            'SUCCESS')
    except MySQLError as err:
        logger.error('Error getting latest snapshot timestamp: {}'.format(err))

    return latest_timestamp

def _get_org_policies(logger, timestamp):
    """Get orgs from data source."""
    org_dao = None
    org_policies = []
    try:
        org_dao = OrganizationDao()
        org_policies = org_dao.get_org_iam_policies(timestamp)
    except MySQLError as err:
        logger.error('Error getting org policies: {}'.format(err))

    return org_policies

def _get_project_policies(logger, timestamp):
    """Get projects from data source."""
    project_dao = None
    project_policies = []
    try:
        project_dao = ProjectDao()
        project_policies = project_dao.get_project_policies(timestamp)
    except MySQLError as err:
        logger.error('Error getting project policies: {}'.format(err))

    return project_policies

def _write_violations_output(logger, violations):
    """Write violations to csv output file and store in output bucket."""
    logger.info('Writing violations to csv...')
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


if __name__ == '__main__':
    app.run()
