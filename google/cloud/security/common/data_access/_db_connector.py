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

import gflags as flags

import MySQLdb
from MySQLdb import OperationalError

from google.cloud.security.common.data_access.errors import MySQLError
from google.cloud.security.common.util.log_util import LogUtil

FLAGS = flags.FLAGS
flags.DEFINE_string('db_host', '127.0.0.1',
                    'Cloud SQL instance hostname/IP address')
flags.DEFINE_string('db_name', 'forseti_security', 'Cloud SQL database name')
flags.DEFINE_string('db_user', 'root', 'Cloud SQL user')
flags.DEFINE_string('db_passwd', None, 'Cloud SQL password')

# pylint: disable=too-few-public-methods
# TODO: Investigate improving so we can avoid the pylint disable.
class _DbConnector(object):
    """Database connector."""

    LOGGER = LogUtil.setup_logging(__name__)

    def __init__(self):
        """Initialize the db connector.

        Raises:
            MySQLError: An error with MySQL has occurred.
        """
        configs = FLAGS.FlagValuesDict()

        try:
            # If specifying the passwd argument, MySQL expects a string,
            # which would not be correct if there is no password (i.e.
            # using cloud_sql_proxy to connect without a db password).
            if 'db_passwd' in configs and configs['db_passwd']:
                self.conn = MySQLdb.connect(
                    host=configs['db_host'],
                    user=configs['db_user'],
                    passwd=configs['db_passwd'],
                    db=configs['db_name'],
                    local_infile=1)
            else:
                self.conn = MySQLdb.connect(
                    host=configs['db_host'],
                    user=configs['db_user'],
                    db=configs['db_name'],
                    local_infile=1)
        except OperationalError as e:
            LOGGER.error('Unable to create mysql connector:\n%s', e)
            raise MySQLError('DB Connector', e)

    def __del__(self):
        """Closes the database connection."""
        try:
            self.conn.close()
        except AttributeError:
            # This happens when conn is not created in the first place,
            # thus does not need to be cleaned up.
            pass
