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
"""Notifier.


Usage:

  $ forseti_notifier --db_host <Cloud SQL database hostname/IP> \\
      --db_user <Cloud SQL database user> \\
      --db_name <Cloud SQL database name (required)> \\
      --config <Notification configuration> \\
      --timestamp <Snapshot timestamp to search for violations>
"""

import importlib
import inspect
import gflags as flags

# pylint: disable=line-too-long,no-name-in-module
from google.apputils import app
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import log_util
from google.cloud.security.notifier.pipelines.base_notification_pipeline import BaseNotificationPipeline
from google.cloud.security.scanner.scanners.scanners_map import RESOURCE_MAP
# pylint: enable=line-too-long,no-name-in-module


# Setup flags
FLAGS = flags.FLAGS

# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# Example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py
flags.DEFINE_string('timestamp', None, 'Snapshot timestamp')
flags.DEFINE_string('config', None, 'Config file to use', short_name='c')

LOGGER = log_util.get_logger(__name__)
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'

def find_pipelines(pipeline_name):
    """Get the first class in the given sub module

    Return:
        The class in the sub module
    """
    try:
        module = importlib.import_module(
            'google.cloud.security.notifier.pipelines.{0}'.format(
                pipeline_name))
        for filename in dir(module):
            obj = getattr(module, filename)

            if inspect.isclass(obj) \
               and issubclass(obj, BaseNotificationPipeline) \
               and obj is not BaseNotificationPipeline:
                return obj
    except ImportError:
        return None

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

def main(_):
    """main function"""
    if FLAGS.timestamp is not None:
        timestamp = FLAGS.timestamp
    else:
        timestamp = _get_timestamp()

    if FLAGS.config is None:
        LOGGER.error('You must specify a notification pipeline')
        exit()

    notifier_configs = FLAGS.FlagValuesDict()
    configs = file_loader.read_and_parse_file(FLAGS.config)

    # get violations
    v_dao = violation_dao.ViolationDao()
    violations = {}
    for resource in RESOURCE_MAP:
        try:
            violations[resource] = v_dao.get_all_violations(
                timestamp, RESOURCE_MAP[resource])
        except Exception as e:
            # even if an error is raised we still want to continue execution
            # this is because if we don't have violations the Mysql table
            # is not present and an error is thrown
            LOGGER.error('get_all_violations error: %s' % e.message)


    for retrieved_v in violations:
        LOGGER.info('retrieved %d violations for resource \'%s\'',
                    len(violations[retrieved_v]), retrieved_v)

    # build notification pipelines
    pipelines = []
    for resource in configs['resources']:
        if violations.get(resource['resource']) is None:
            LOGGER.error('The resource name \'%s\' is invalid, skipping',
                         resource['resource'])
            continue
        if resource['should_notify'] is False:
            continue
        for pipeline in resource['pipelines']:
            LOGGER.info('Running \'%s\' pipeline for resource \'%s\'',
                        pipeline['name'], resource['resource'])
            chosen_pipeline = find_pipelines(pipeline['name'])
            pipelines.append(chosen_pipeline(resource['resource'],
                                             timestamp,
                                             violations[resource['resource']],
                                             notifier_configs,
                                             pipeline['configuration']))

    # run the pipelines
    for pipeline in pipelines:
        pipeline.run()


if __name__ == '__main__':
    app.run()
