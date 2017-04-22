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

"""Provides the data access object (DAO) for Organizations."""

import MySQLdb

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access.sql_queries import load_data
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ViolationDao(dao.Dao):
    """Data access object (DAO) for rule violations."""

    RESOURCE_NAME = 'violations'

    def import_violations(self, violations, snapshot_timestamp=None):
        """Import violations into database.

        Args:
            violations: An iterator of RuleViolations.
            snapshot_timestamp: The snapshot timestamp to associate these
                violations with.

        Raise:
            MySQLError if an error occurs while loading the violations into
            the database.
        """

        try:
            # Make sure to have a reasonable timestamp to use.
            if not snapshot_timestamp:
                snapshot_timestamp = self.get_latest_snapshot_timestamp(
                    ('PARTIAL_SUCCESS', 'SUCCESS'))

            # Create the violations snapshot table.
            snapshot_table = self._create_snapshot_table(
                self.RESOURCE_NAME, snapshot_timestamp)
        except MySQLdb.Error, e:
            raise db_errors.MySQLError(self.RESOURCE_NAME, e)

        try:
            # Insert the violations to the table in one single transaction.
            self.conn.autocommit(False)
            cursor = self.conn.cursor()
            for violation in violations:
                for formatted_violation in _format_violation(violation):
                    cursor.execute(
                        load_data.INSERT_VIOLATION.format(snapshot_table),
                        formatted_violation)
            self.conn.commit()
        except MySQLdb.Error, e:
            self.conn.rollback()
            raise db_errors.MySQLError(self.RESOURCE_NAME, e)
        finally:
            self.conn.autocommit(True)

def _format_violation(violation):
    """Format the violation data into a tuple.

    Also flattens the RuleViolation, since it consists of the resource,
    rule, and members that don't meet the rule criteria.

    Args:
        violation: The RuleViolation.

    Returns:
        A tuple of the rule violation properties.
    """

    resource_type = violation.resource_type
    if resource_type:
        resource_type = resource_type[:255]

    resource_id = violation.resource_id
    if resource_id:
        resource_id = str(resource_id)[:255]

    rule_name = violation.rule_name
    if rule_name:
        rule_name = rule_name[:255]

    role = violation.role
    if role:
        role = role[:255]

    iam_members = violation.members
    if iam_members:
        members = [str(iam_member)[:255] for iam_member in iam_members]
    else:
        members = []

    for member in members:
        yield (resource_type,
               resource_id,
               rule_name,
               violation.rule_index,
               violation.violation_type,
               role,
               member)
