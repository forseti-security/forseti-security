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
from google.cloud.security.common.util import file_loader
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

# Hack to make the test pass due to duplicate flag error here
# and scanner, enforcer.
# TODO: Find a way to remove this try/except, possibly dividing the tests
# into different test suites.
try:
    flags.DEFINE_string('config_path', None,
                        'Path to the Forseti config file.')
except flags.DuplicateFlagError:
    pass


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

def _create_dao_map(global_configs):
    """Create a map of DAOs.

    These will be re-usable so that the db connection can apply across
    different pipelines.

    Args:
        global_configs (dict): Global configurations.

    Returns:
        dict: Dictionary of DAOs.
    """
    try:
        return {
            'appengine_dao': appengine_dao.AppEngineDao(global_configs),
            'backend_service_dao':
                backend_service_dao.BackendServiceDao(global_configs),
            'bucket_dao': bucket_dao.BucketDao(global_configs),
            'cloudsql_dao': cloudsql_dao.CloudsqlDao(global_configs),
            'dao': dao.Dao(global_configs),
            'folder_dao': folder_dao.FolderDao(global_configs),
            'forwarding_rules_dao':
                forwarding_rules_dao.ForwardingRulesDao(global_configs),
            'instance_dao': instance_dao.InstanceDao(global_configs),
            'instance_group_dao':
                instance_group_dao.InstanceGroupDao(global_configs),
            'instance_group_manager_dao':
                instance_group_manager_dao.InstanceGroupManagerDao(
                    global_configs),
            'instance_template_dao':
                instance_template_dao.InstanceTemplateDao(global_configs),
            'organization_dao': organization_dao.OrganizationDao(
                global_configs),
            'project_dao': project_dao.ProjectDao(global_configs),
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

    _configure_logging(inventory_flags.get('loglevel'))

    if inventory_flags.get('list_resources'):
        inventory_util.list_resource_pipelines()
        sys.exit()

    config_path = inventory_flags.get('config_path')
    if config_path is None:
        LOGGER.error('Path to forseti config needs to be specified.')
        sys.exit()

    configs = file_loader.read_and_parse_file(config_path)
    global_configs = configs.get('global')
    inventory_configs = configs.get('inventory')

    dao_map = _create_dao_map(global_configs)

    cycle_time, cycle_timestamp = _start_snapshot_cycle(dao_map.get('dao'))

    pipeline_builder = builder.PipelineBuilder(
        cycle_timestamp,
        inventory_configs,
        global_configs,
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

    if global_configs.get('email_recipient') is not None:
        payload = {
            'email_sender': global_configs.get('email_sender'),
            'email_recipient': global_configs.get('email_recipient'),
            'sendgrid_api_key': global_configs.get('sendgrid_api_key'),
            'cycle_time': cycle_time,
            'cycle_timestamp': cycle_timestamp,
            'snapshot_cycle_status': snapshot_cycle_status,
            'pipelines': pipelines
        }
        message = {
            'status': 'inventory_done',
            'payload': payload
        }
        notifier.process(message)


if __name__ == '__main__':
    app.run()
