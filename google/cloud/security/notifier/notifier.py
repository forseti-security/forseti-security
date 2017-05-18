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

from datetime import datetime

import gflags as flags

from google.apputils import app
from google.cloud.security.common.data_access import csv_writer
from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import violation_dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.scanner.audit import engine_map as em
from google.cloud.security.scanner.scanners import scanners_map as sm
from google.cloud.security.notifier.pipelines.notification_pipeline import NotificationPipeline
from google.cloud.security.notifier.pipelines import spotify_pipeline
import importlib
import inspect

# Setup flags
FLAGS = flags.FLAGS

# Format: flags.DEFINE_<type>(flag_name, default_value, help_text)
# Example:
# https://github.com/google/python-gflags/blob/master/examples/validator.py
flags.DEFINE_string('timestamp', None, 'Snapshot timestamp')
flags.DEFINE_string('pipeline', None, 'Pipeline to use')

LOGGER = log_util.get_logger(__name__)
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'

def find_pipelines(pipeline_name):
    try:
        module = importlib.import_module('google.cloud.security.notifier.pipelines.{0}'.format(pipeline_name))
        for x in dir(module):
            obj = getattr(module, x)

            if inspect.isclass(obj) and issubclass(obj, NotificationPipeline) and obj is not NotificationPipeline:
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
    timestamp = FLAGS.timestamp if FLAGS.timestamp is not None \
                else _get_timestamp()

    if FLAGS.pipeline is None:
        LOGGER.error('You must sepcify a notification pipeline')
        exit()

    configs = FLAGS.FlagValuesDict()

    chosen_pipeline = find_pipelines(FLAGS.pipeline)
    pipelines = [
        chosen_pipeline(timestamp, configs),
    ]

    for p in pipelines:
        p.run()


if __name__ == '__main__':
    app.run()
