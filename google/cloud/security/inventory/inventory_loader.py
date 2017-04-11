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

"""Loads requested data into inventory.

Usage examples: docs/inventory/README.md

Usage:
  $ forseti_inventory \\
      --inventory_groups <true|false> (optional) \\
      --groups_service_account_key_file <path to file> (optional)\\
      --domain_super_admin_email <user@domain.com> (optional) \\
      --organization_id <organization_id> (required) \\
      --db_host <Cloud SQL database hostname/IP> (required) \\
      --db_user <Cloud SQL database user> (required) \\
      --db_name <Cloud SQL database name (required)> \\
      --max_crm_api_calls_per_100_seconds <default: 400> (optional) \\
      --max_admin_api_calls_per_day <default: 150000> (optional)  \\
      --sendgrid_api_key <API key to auth SendGrid email service> (optional) \\
      --email_sender <email address of the email sender> (optional) \\
      --email_recipient <email address of the email recipient> (optional)

To see all the dependent flags:
  $ forseti_inventory --helpfull

"""

from datetime import datetime
import sys

import gflags as flags

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.apputils import app
from google.cloud.security.common.data_access import db_schema_version
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access.dao import Dao
from google.cloud.security.common.data_access.sql_queries import snapshot_cycles_sql
from google.cloud.security.common.gcp_api import admin_directory as ad
from google.cloud.security.common.gcp_api import cloud_resource_manager as crm
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.common.util.errors import EmailSendError
from google.cloud.security.inventory.errors import LoadDataPipelineError
from google.cloud.security.inventory.pipelines import load_groups_pipeline
from google.cloud.security.inventory.pipelines import load_group_members_pipeline
from google.cloud.security.inventory.pipelines import load_org_iam_policies_pipeline
from google.cloud.security.inventory.pipelines import load_projects_iam_policies_pipeline
from google.cloud.security.inventory.pipelines import load_projects_pipeline
from google.cloud.security.inventory import util
# pylint: enable=line-too-long

FLAGS = flags.FLAGS

flags.DEFINE_bool('inventory_groups', False,
                  'Whether to inventory GSuite Groups.')
flags.DEFINE_string('organization_id', None, 'Organization ID.')

flags.mark_flag_as_required('organization_id')

# YYYYMMDDTHHMMSSZ, e.g. 20170130T192053Z
CYCLE_TIMESTAMP_FORMAT = '%Y%m%dT%H%M%SZ'

LOGGER = log_util.get_logger(__name__)


def _exists_snapshot_cycles_table(dao):
    """Whether the snapshot_cycles table exists.

    Args:
        dao: Data access object.

    Returns:
        True if the snapshot cycle table exists. False otherwise.

    Raises:
        MySQLError: An error with MySQL has occurred.
    """
    try:
        sql = snapshot_cycles_sql.SELECT_SNAPSHOT_CYCLES_TABLE
        result = dao.execute_sql_with_fetch(snapshot_cycles_sql.RESOURCE_NAME,
                                            sql, values=None)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Error in attempt to find snapshot_cycles table: %s', e)
        sys.exit()

    if len(result) > 0 and result[0]['TABLE_NAME'] == 'snapshot_cycles':
        return True
    return False

def _create_snapshot_cycles_table(dao):
    """Create snapshot cycle table.

    Args:
        dao: Data access object.

    Raises:
        MySQLError: An error with MySQL has occurred.
    """

    try:
        sql = snapshot_cycles_sql.CREATE_TABLE
        dao.execute_sql_with_commit(snapshot_cycles_sql.RESOURCE_NAME,
                                    sql, values=None)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Unable to create snapshot cycles table: %s', e)
        sys.exit()

def _start_snapshot_cycle(dao):
    """Start snapshot cycle.

    Args:
        dao: Data access object.

    Returns:
        cycle_time: Datetime object of the cycle, in UTC.
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.

    Raises:
        MySQLError: An error with MySQL has occurred.
    """
    cycle_time = datetime.utcnow()
    cycle_timestamp = cycle_time.strftime(CYCLE_TIMESTAMP_FORMAT)

    if not _exists_snapshot_cycles_table(dao):
        LOGGER.info('snapshot_cycles is not created yet.')
        _create_snapshot_cycles_table(dao)

    try:
        sql = snapshot_cycles_sql.INSERT_CYCLE
        values = (cycle_timestamp, cycle_time, 'RUNNING', db_schema_version)
        dao.execute_sql_with_commit(snapshot_cycles_sql.RESOURCE_NAME,
                                    sql, values)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Unable to insert new snapshot cycle: %s', e)
        sys.exit()

    LOGGER.info('Inventory snapshot cycle started: %s', cycle_timestamp)
    return cycle_time, cycle_timestamp

def _build_pipelines(cycle_timestamp, configs, dao):
    """Build the pipelines to load data.

    Args:
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        configs: Dictionary of configurations.
        dao: Data access object.

    Returns:
        List of pipelines that will be run.

    Raises: inventory_errors.LoadDataPipelineError.
    """
    pipelines = []
    crm_api_client = crm.CloudResourceManagerClient()

    # The order here matters, e.g. groups_pipeline must come before
    # group_members_pipeline.
    pipelines = [
        load_org_iam_policies_pipeline.LoadOrgIamPoliciesPipeline(
            cycle_timestamp, configs, crm_api_client, dao),
        load_projects_pipeline.LoadProjectsPipeline(
            cycle_timestamp, configs, crm_api_client, dao),
        load_projects_iam_policies_pipeline.LoadProjectsIamPoliciesPipeline(
            cycle_timestamp, configs, crm_api_client, dao)
    ]

    if configs.get('inventory_groups'):
        if util.can_inventory_groups(configs):
            admin_api_client = ad.AdminDirectoryClient()
            pipelines.extend([
                load_groups_pipeline.LoadGroupsPipeline(
                    cycle_timestamp, configs, admin_api_client, dao),
                load_group_members_pipeline.LoadGroupMembersPipeline(
                    cycle_timestamp, configs, admin_api_client, dao)
            ])
        else:
            raise inventory_errors.LoadDataPipelineError(
                'Unable to inventory groups with specified arguments:\n%s',
                self.configs)

def _run_pipelines(pipelines):
    """Run the pipelines to load data.

    Args:
        pipelines: List of pipelines to be run.

    Returns:
        run_statuses: List of boolean whether each pipeline was run
            successfully or not.
    """
    # TODO: Define these status codes programmatically.
    run_statuses = []
    for pipeline in pipelines:
        try:
            pipeline.run()
            pipeline.status = 'SUCCESS'
        except LoadDataPipelineError as e:
            LOGGER.error('Encountered error loading data.\n%s', e)
            pipeline.status = 'FAILURE'
            LOGGER.info('Continuing on.')
        run_statuses.append(pipeline.status == 'SUCCESS')
    return run_statuses

def _complete_snapshot_cycle(dao, cycle_timestamp, status):
    """Complete the snapshot cycle.

    Args:
        dao: Data access object.
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        status: String of the current cycle's status.

    Returns:
         None

    Raises:
        MySQLError: An error with MySQL has occurred.
    """
    complete_time = datetime.utcnow()

    try:
        values = (status, complete_time, cycle_timestamp)
        sql = snapshot_cycles_sql.UPDATE_CYCLE
        dao.execute_sql_with_commit(snapshot_cycles_sql.RESOURCE_NAME,
                                    sql, values)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Unable to complete update snapshot cycle: %s', e)
        sys.exit()

    LOGGER.info('Inventory load cycle completed with %s: %s',
                status, cycle_timestamp)

def _send_email(organization_id, cycle_time, cycle_timestamp, status, pipelines,
                sendgrid_api_key, email_sender, email_recipient,
                email_content=None):
    """Send an email.

    Args:
        organization_id: String of the organization id
        cycle_time: Datetime object of the cycle, in UTC.
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        status: String of the overall status of current snapshot cycle.
        pipelines: List of pipelines and their statuses.
        sendgrid_api_key: String of the sendgrid api key to auth email service.
        email_sender: String of the sender of the email.
        email_recipient: String of the recipient of the email.
        email_content: String of the email content (aka, body).

    Returns:
         None
    """

    email_subject = 'Inventory Snapshot Complete: {0} {1}'.format(
        cycle_timestamp, status)

    email_content = EmailUtil.render_from_template(
        'inventory_snapshot_summary.jinja', {
            'organization_id': organization_id,
            'cycle_time': cycle_time.strftime('%Y %b %d, %H:%M:%S (UTC)'),
            'cycle_timestamp': cycle_timestamp,
            'status_summary': status,
            'pipelines': pipelines,
        })

    try:
        email_util = EmailUtil(sendgrid_api_key)
        email_util.send(email_sender, email_recipient,
                        email_subject, email_content,
                        content_type='text/html')
    except EmailSendError:
        LOGGER.error('Unable to send email that inventory snapshot completed.')

def main(_):
    """Runs the Inventory Loader."""
    try:
        dao = Dao()
    except data_access_errors.MySQLError as e:
        LOGGER.error('Encountered error with Cloud SQL. Abort.\n%s', e)
        sys.exit()

    cycle_time, cycle_timestamp = _start_snapshot_cycle(dao)

    configs = FLAGS.FlagValuesDict()

    try:
        pipelines = _build_pipelines(cycle_timestamp, configs, dao)
    except api_errors.ApiExecutionError as e:
        LOGGER.error('Unable to build pipelines.\n%s', e)
        sys.exit()

    run_statuses = _run_pipelines(pipelines)
    if all(run_statuses):
        snapshot_cycle_status = 'SUCCESS'
    elif any(run_statuses):
        snapshot_cycle_status = 'PARTIAL_SUCCESS'
    else:
        snapshot_cycle_status = 'FAILURE'

    _complete_snapshot_cycle(dao, cycle_timestamp, snapshot_cycle_status)

    if configs.get('email_recipient') is not None:
        _send_email(configs.get('organization_id'),
                    cycle_time,
                    cycle_timestamp,
                    snapshot_cycle_status,
                    pipelines,
                    configs.get('sendgrid_api_key'),
                    configs.get('email_sender'),
                    configs.get('email_recipient'))


if __name__ == '__main__':
    app.run()
