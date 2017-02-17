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

"""Provides the database connector."""

import logging
import os

import MySQLdb
import yaml

from google.cloud.security import FORSETI_SECURITY_HOME_ENV_VAR


# TODO: Reference this by an absolute path so that it works locally
# and on GCE.
CONFIGS_FILE = os.path.abspath(
    os.path.join(os.environ.get(FORSETI_SECURITY_HOME_ENV_VAR),
                 'config', 'db.yaml'))


class _DbConnector(object):
    """Database connector."""

    def __init__(self):
        with open(CONFIGS_FILE, 'r') as config_file:
            try:
                configs = yaml.load(config_file)
            except yaml.YAMLError as e:
                logging.error(e)

        self.conn = MySQLdb.connect(
            host=configs['cloud_sql']['host'],
            user=configs['cloud_sql']['user'],
            passwd=configs['cloud_sql']['passwd'],
            db=configs['cloud_sql']['database'],
            local_infile=1)

    def __del__(self):
        """Closes the database connection."""
        self.conn.close()
