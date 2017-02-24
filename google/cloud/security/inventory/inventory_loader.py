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

  $ forseti_inventory --config <config filepath>

"""

from datetime import datetime
import gflags as flags
import logging
import os
import sys
import yaml

from ratelimiter import RateLimiter

from google.apputils import app
from google.cloud.security.common.data_access import db_schema_version
from google.cloud.security.common.data_access.dao import Dao
from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.data_access.sql_queries import snapshot_cycles_sql
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.inventory.errors import LoadDataPipelineError
from google.cloud.security.inventory.pipelines import load_iam_policies_pipeline
from google.cloud.security.inventory.pipelines import load_projects_pipeline


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
        timestamp: String of timestamp, formatted as YYYYMMDDTHHMMSSZ.
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

def main(unused_argv=None):
    """Runs the Inventory Loader."""

    try:
        dao = Dao()
    except MySQLError as e:
        LOGGER.error('Encountered error with Cloud SQL. Abort.\n{0}'.format(e))
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

    try:
        load_projects_pipeline.run(
            dao, cycle_timestamp, configs, crm_rate_limiter)
        load_iam_policies_pipeline.run(
            dao, cycle_timestamp, configs, crm_rate_limiter)
    except LoadDataPipelineError as e:
        LOGGER.error('Encountered error to load data. Abort.\n{0}'.format(e))
        _complete_snapshot_cycle(dao, cycle_timestamp, 'FAILURE')
        sys.exit()

    _complete_snapshot_cycle(dao, cycle_timestamp, 'SUCCESS')


if __name__ == '__main__':
    app.run()
