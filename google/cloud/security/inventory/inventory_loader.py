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

"""Loads data into Inventory.

Usage:

  $ forseti_inventory \\
      --organization_id <organization_id> (required) \\
      --db_host <Cloud SQL database hostname/IP> \\
      --db_user <Cloud SQL database user> \\
      --db_passwd <Cloud SQL database password> \\
      --db_name <Cloud SQL database name (required)> \\
      --max_crm_api_calls_per_100_seconds <QPS * 100, default 400> \\
      --sendgrid_api_key <API key to auth SendGrid email service (required)> \\
      --email_sender <email address of the email sender> (required) \\
      --email_recipient <email address of the email recipient> (required)

To see all the dependent flags:

  $ forseti_inventory --helpfull
"""

import sys

from datetime import datetime
import gflags as flags

from ratelimiter import RateLimiter

from google.apputils import app
from google.cloud.security.common.data_access import db_schema_version
from google.cloud.security.common.data_access.dao import Dao
from google.cloud.security.common.data_access.errors import MySQLError
# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.data_access.sql_queries import snapshot_cycles_sql
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.common.util.errors import EmailSendError
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.inventory.errors import LoadDataPipelineError
from google.cloud.security.inventory.pipelines import load_org_iam_policies_pipeline
from google.cloud.security.inventory.pipelines import load_projects_iam_policies_pipeline
from google.cloud.security.inventory.pipelines import load_projects_pipeline
# pylint: enable=line-too-long

FLAGS = flags.FLAGS

flags.DEFINE_integer('max_crm_api_calls_per_100_seconds', 400,
                     'Cloud Resource Manager queries per 100 seconds.')

flags.DEFINE_string('organization_id', None, 'Organization ID.')

flags.mark_flag_as_required('organization_id')

# YYYYMMDDTHHMMSSZ, e.g. 20170130T192053Z
CYCLE_TIMESTAMP_FORMAT = '%Y%m%dT%H%M%SZ'

LOGGER = LogUtil.setup_logging(__name__)


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
    except MySQLError as e:
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
    except MySQLError as e:
        LOGGER.error('Unable to create snapshot cycles table: %s', e)
        sys.exit()

def _start_snapshot_cycle(dao):
    """Start snapshot cycle.

    Args:
        dao: Data access object.

    Returns:
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
    except MySQLError as e:
        LOGGER.error('Unable to insert new snapshot cycle: %s', e)
        sys.exit()

    LOGGER.info('Inventory snapshot cycle started: %s', cycle_timestamp)
    return cycle_timestamp

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
    except MySQLError as e:
        LOGGER.error('Unable to complete update snapshot cycle: %s', e)
        sys.exit()

    LOGGER.info('Inventory load cycle completed with %s: %s',
                status, cycle_timestamp)

def _send_email(cycle_timestamp, status, sendgrid_api_key,
                email_sender, email_recipient, email_content=None):
    """Send an email.

    Args:
        cycle_timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
        status: String of the current snapshot cycle.
        sendgrid_api_key: String of the sendgrid api key to auth email service.
        email_sender: String of the sender of the email.
        email_recipient: String of the recipient of the email.
        email_content: String of the email content (aka, body).

    Returns:
         None
    """
    email_subject = 'Inventory loading {0}: {1}'.format(cycle_timestamp, status)

    if email_content is None:
        email_content = email_subject

    try:
        email_util = EmailUtil(sendgrid_api_key)
        email_util.send(email_sender, email_recipient,
                        email_subject, email_content)
    except EmailSendError:
        LOGGER.error('Unable to send email that inventory snapshot completed.')

def main():
    """Runs the Inventory Loader."""

    try:
        dao = Dao()
    except MySQLError as e:
        LOGGER.error('Encountered error with Cloud SQL. Abort.\n%s', e)
        sys.exit()

    cycle_timestamp = _start_snapshot_cycle(dao)

    configs = FLAGS.FlagValuesDict()

    # It's better to build the ratelimiters once for each API
    # and reuse them across multiple instances of the Client.
    # Otherwise, there is a gap where the ratelimiter from one pipeline
    # is not used for the next pipeline using the same API. This could
    # lead to unnecessary quota errors.
    max_crm_calls = configs.get('max_crm_api_calls_per_100_seconds', 400)
    crm_rate_limiter = RateLimiter(max_crm_calls, 100)

    pipelines = [
        {'pipeline': load_projects_pipeline,
         'status': ''},
        {'pipeline': load_projects_iam_policies_pipeline,
         'status': ''},
        {'pipeline': load_org_iam_policies_pipeline,
         'status': ''},
    ]

    for pipeline in pipelines:
        try:
            pipeline['pipeline'].run(
                dao, cycle_timestamp, configs, crm_rate_limiter)
            pipeline['status'] = 'SUCCESS'
        except LoadDataPipelineError as e:
            LOGGER.error(
                'Encountered error to load data.\n%s', e)
            pipeline['status'] = 'FAILURE'

    succeeded = [p['status'] == 'SUCCESS' for p in pipelines]

    if all(succeeded):
        snapshot_cycle_status = 'SUCCESS'
    elif any(succeeded):
        snapshot_cycle_status = 'PARTIAL_SUCCESS'
    else:
        snapshot_cycle_status = 'FAILURE'

    _complete_snapshot_cycle(dao, cycle_timestamp, snapshot_cycle_status)
    _send_email(cycle_timestamp, snapshot_cycle_status,
                configs.get('sendgrid_api_key'),
                configs.get('email_sender'), configs.get('email_recipient'))


if __name__ == '__main__':
    app.run()
