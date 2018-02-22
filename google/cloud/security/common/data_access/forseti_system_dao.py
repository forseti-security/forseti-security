# Copyright 2017 The Forseti Security Authors. All rights reserved.
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

"""Provides the data access object (DAO) for Forseti system management."""

from google.cloud.security.common.data_access import dao
# pylint: disable=line-too-long
from google.cloud.security.common.data_access.sql_queries import cleanup_tables_sql
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class ForsetiSystemDao(dao.Dao):
    """Data access object (DAO) for Forseti system management.

    Args:
            global_configs (dict): Global config - used to lookup db_name
    """
    def __init__(self, global_configs=None):
        dao.Dao.__init__(self, global_configs)
        self.db_name = global_configs['db_name']

    def cleanup_inventory_tables(self, retention_days):
        """Clean up old inventory tables based on their age

        Will detect tables based on snapshot start time in snapshot table,
        and drop tables older than retention_days specified.

        Args:
            retention_days (int): Days of inventory tables to retain.
        """
        sql = cleanup_tables_sql.SELECT_SNAPSHOT_TABLES_OLDER_THAN
        result = self.execute_sql_with_fetch(
            cleanup_tables_sql.RESOURCE_NAME,
            sql,
            [retention_days, self.db_name])

        LOGGER.info(
            'Found %s tables to clean up that are older than %s days',
            len(result),
            retention_days)

        for row in result:
            LOGGER.debug('Dropping table: %s', row['table'])
            self.execute_sql_with_commit(
                cleanup_tables_sql.RESOURCE_NAME,
                cleanup_tables_sql.DROP_TABLE.format(row['table']),
                None)
