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

# TODO: Move all these flags to the config file.

"""Loads requested data into inventory.

Usage:
  $ forseti_inventory \\
      --config_path (required) \\
      --groups_service_account_key_file <path to file> (optional)\\
      --domain_super_admin_email <user@domain.com> (optional) \\
      --db_host <Cloud SQL database hostname/IP> (required) \\
      --db_user <Cloud SQL database user> (required) \\
      --db_name <Cloud SQL database name (required)> \\
      --max_crm_api_calls_per_100_seconds <default: 400> (optional) \\
      --max_admin_api_calls_per_day <default: 150000> (optional) \\
      --max_bigquery_api_calls_per_day <default: 17000> (optional) \\
      --sendgrid_api_key <API key to auth SendGrid email service> (optional) \\
      --email_sender <email address of the email sender> (optional) \\
      --email_recipient <email address of the email recipient> (optional) \\
      --loglevel <debug|info|warning|error>

To see all the dependent flags:
  $ forseti_inventory --helpfull

"""
from datetime import datetime
import logging
import sys

import gflags as flags

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.apputils import app
from google.cloud.security.common.data_access import appengine_dao
from google.cloud.security.common.data_access import backend_service_dao
from google.cloud.security.common.data_access import bucket_dao
from google.cloud.security.common.data_access import cloudsql_dao
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import db_schema_version
from google.cloud.security.common.data_access import errors as data_access_errors
from google.cloud.security.common.data_access import folder_dao
from google.cloud.security.common.data_access import forwarding_rules_dao
from google.cloud.security.common.data_access import instance_dao
from google.cloud.security.common.data_access import instance_group_dao
from google.cloud.security.common.data_access import instance_group_manager_dao
from google.cloud.security.common.data_access import instance_template_dao
from google.cloud.security.common.data_access import organization_dao
from google.cloud.security.common.data_access import project_dao
from google.cloud.security.common.data_access.sql_queries import snapshot_cycles_sql
from google.cloud.security.common.gcp_api import errors as api_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.inventory import api_map
from google.cloud.security.inventory import errors as inventory_errors
from google.cloud.security.inventory import pipeline_builder as builder
from google.cloud.security.inventory import util as inventory_util
from google.cloud.security.notifier import notifier
# pylint: enable=line-too-long


FLAGS = flags.FLAGS

LOGLEVELS = {
    'debug': logging.DEBUG,
    'info' : logging.INFO,
    'warning' : logging.WARN,
    'error' : logging.ERROR,
}
flags.DEFINE_enum('loglevel', 'info', LOGLEVELS.keys(), 'Loglevel.')

flags.DEFINE_boolean('list_resources', False,
                     'List valid resources for --config_path.')

# These flags are for the admin.py module.
flags.DEFINE_string('config_path', None,
                    'Path to the inventory config file.')

flags.DEFINE_string('domain_super_admin_email', None,
                    'An email address of a super-admin in the GSuite domain. '
                    'REQUIRED: if inventory_groups is enabled.')
flags.DEFINE_string('groups_service_account_key_file', None,
                    'The key file with credentials for the service account. '
                    'REQUIRED: If inventory_groups is enabled and '
                    'runnning locally.')
flags.DEFINE_integer('max_admin_api_calls_per_day', 150000,
                     'Admin SDK queries per day.')
flags.DEFINE_string('max_results_admin_api', 500,
                    'maxResult param for the Admin SDK list() method')


# YYYYMMDDTHHMMSSZ, e.g. 20170130T192053Z
CYCLE_TIMESTAMP_FORMAT = '%Y%m%dT%H%M%SZ'

LOGGER = log_util.get_logger(__name__)


def _exists_snapshot_cycles_table(inventory_dao):
    """Whether the snapshot_cycles table exists.

    Args:
        inventory_dao (data_access.Dao): Data access object.

    Returns:
        bool: True if the snapshot cycle table exists. False otherwise.
    """
    try:
        sql = snapshot_cycles_sql.SELECT_SNAPSHOT_CYCLES_TABLE
        result = inventory_dao.execute_sql_with_fetch(
            snapshot_cycles_sql.RESOURCE_NAME, sql, values=None)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Error in attempt to find snapshot_cycles table: %s', e)
        sys.exit()

    if result and result[0]['TABLE_NAME'] == 'snapshot_cycles':
        return True

    return False

def _create_snapshot_cycles_table(inventory_dao):
    """Create snapshot cycle table.

    Args:
        inventory_dao (data_access.Dao): Data access object.

    Returns:
    """
    try:
        sql = snapshot_cycles_sql.CREATE_TABLE
        inventory_dao.execute_sql_with_commit(snapshot_cycles_sql.RESOURCE_NAME,
                                              sql, values=None)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Unable to create snapshot cycles table: %s', e)
        sys.exit()

def _start_snapshot_cycle(inventory_dao):
    """Start snapshot cycle.

    Args:
        inventory_dao (dao.Dao): Data access object.

    Returns:
        datetime: Datetime object for the cycle_time, in UTC.
        str: String of cycle_timestamp, formatted as YYYYMMDDTHHMMSSZ.
    """
    cycle_time = datetime.utcnow()
    cycle_timestamp = cycle_time.strftime(CYCLE_TIMESTAMP_FORMAT)

    if not _exists_snapshot_cycles_table(inventory_dao):
        LOGGER.info('snapshot_cycles is not created yet.')
        _create_snapshot_cycles_table(inventory_dao)

    try:
        sql = snapshot_cycles_sql.INSERT_CYCLE
        values = (cycle_timestamp, cycle_time, 'RUNNING', db_schema_version)
        inventory_dao.execute_sql_with_commit(snapshot_cycles_sql.RESOURCE_NAME,
                                              sql, values)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Unable to insert new snapshot cycle: %s', e)
        sys.exit()

    LOGGER.info('Inventory snapshot cycle started: %s', cycle_timestamp)
    return cycle_time, cycle_timestamp

def _run_pipelines(pipelines):
    """Run the pipelines to load data.

    Args:
        pipelines (list): List of pipelines to be run.

    Returns:
        list: a list of booleans whether each pipeline completed
            successfully or not.
    """
    # TODO: Define these status codes programmatically.
    run_statuses = []
    for pipeline in pipelines:
        try:
            LOGGER.debug('Running pipeline %s', pipeline.__class__.__name__)
            pipeline.run()
            pipeline.status = 'SUCCESS'
        except (api_errors.ApiInitializationError,
                inventory_errors.LoadDataPipelineError) as e:
            LOGGER.error('Encountered error loading data.\n%s', e)
            pipeline.status = 'FAILURE'
            LOGGER.info('Continuing on.')
        run_statuses.append(pipeline.status == 'SUCCESS')
    return run_statuses

def _complete_snapshot_cycle(inventory_dao, cycle_timestamp, status):
    """Complete the snapshot cycle.

    Args:
        inventory_dao (dao.Dao): Data access object.
        cycle_timestamp (str): Timestamp, formatted as YYYYMMDDTHHMMSSZ.
        status (str): The current cycle's status.

    Returns:
    """
    complete_time = datetime.utcnow()

    try:
        values = (status, complete_time, cycle_timestamp)
        sql = snapshot_cycles_sql.UPDATE_CYCLE
        inventory_dao.execute_sql_with_commit(snapshot_cycles_sql.RESOURCE_NAME,
                                              sql, values)
    except data_access_errors.MySQLError as e:
        LOGGER.error('Unable to complete update snapshot cycle: %s', e)
        sys.exit()

    LOGGER.info('Inventory load cycle completed with %s: %s',
                status, cycle_timestamp)

def _configure_logging(loglevel):
    """Configures the loglevel for all loggers.

    Args:
        loglevel (str): The loglevel to set.

    Returns:
    """
    level = LOGLEVELS.setdefault(loglevel, 'info')
    log_util.set_logger_level(level)

def _create_dao_map():
    """Create a map of DAOs.

    These will be re-usable so that the db connection can apply across
    different pipelines.

    Returns:
        dict: Dictionary of DAOs.
    """
    try:
        return {
            'appengine_dao': appengine_dao.AppEngineDao(),
            'backend_service_dao': backend_service_dao.BackendServiceDao(),
            'bucket_dao': bucket_dao.BucketDao(),
            'cloudsql_dao': cloudsql_dao.CloudsqlDao(),
            'dao': dao.Dao(),
            'folder_dao': folder_dao.FolderDao(),
            'forwarding_rules_dao': forwarding_rules_dao.ForwardingRulesDao(),
            'instance_dao': instance_dao.InstanceDao(),
            'instance_group_dao': instance_group_dao.InstanceGroupDao(),
            'instance_group_manager_dao':
                instance_group_manager_dao.InstanceGroupManagerDao(),
            'instance_template_dao':
                instance_template_dao.InstanceTemplateDao(),
            'organization_dao': organization_dao.OrganizationDao(),
            'project_dao': project_dao.ProjectDao(),
        }
    except data_access_errors.MySQLError as e:
        LOGGER.error('Error to creating DAO map.\n%s', e)
        sys.exit()

def main(_):
    """Runs the Inventory Loader.

    Args:
        _ (list): args that aren't used

    Returns:
    """
    del _
    inventory_flags = FLAGS.FlagValuesDict()

    if inventory_flags.get('list_resources'):
        inventory_util.list_resource_pipelines()
        sys.exit()

    _configure_logging(inventory_flags.get('loglevel'))

    config_path = inventory_flags.get('config_path')

    if config_path is None:
        LOGGER.error('Path to pipeline config needs to be specified.')
        sys.exit()

    dao_map = _create_dao_map()

    cycle_time, cycle_timestamp = _start_snapshot_cycle(dao_map.get('dao'))

    pipeline_builder = builder.PipelineBuilder(
        cycle_timestamp,
        config_path,
        flags,
        api_map.API_MAP,
        dao_map)
    pipelines = pipeline_builder.build()

    run_statuses = _run_pipelines(pipelines)

    if all(run_statuses):
        snapshot_cycle_status = 'SUCCESS'
    elif any(run_statuses):
        snapshot_cycle_status = 'PARTIAL_SUCCESS'
    else:
        snapshot_cycle_status = 'FAILURE'

    _complete_snapshot_cycle(dao_map.get('dao'), cycle_timestamp,
                             snapshot_cycle_status)

    if inventory_flags.get('email_recipient') is not None:
        message_data = {
            'email_sender': inventory_flags.get('email_sender'),
            'email_recipient': inventory_flags.get('email_recipient'),
            'sendgrid_api_key': inventory_flags.get('sendgrid_api_key'),
            'cycle_time': cycle_time,
            'cycle_timestamp': cycle_timestamp,
            'snapshot_cycle_status': snapshot_cycle_status,
            'pipelines': pipelines
        }
        message = {
            'status': 'inventory_done',
            'data': message_data
        }
        notifier.process(message)


if __name__ == '__main__':
    app.run()
