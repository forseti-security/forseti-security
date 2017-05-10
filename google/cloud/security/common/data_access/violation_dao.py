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
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ViolationDao(dao.Dao):
    """Data access object (DAO) for rule violations."""

    RESOURCE_NAME = 'violations'

    def insert_violations(self, violations, snapshot_timestamp=None):
        """Import violations into database.

        Args:
            violations: An iterator of RuleViolations.
            snapshot_timestamp: The snapshot timestamp to associate these
                violations with.

        Return:
            A tuple of (int, list) containing the count of inserted rows and
            a list of violations that encountered an error during insert.

        Raise:
            MySQLError if snapshot table could not be created.
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

        inserted_rows = 0
        violation_errors = []
        for violation in violations:
            for formatted_violation in _format_violation(violation):
                try:
                    self.execute_sql_with_commit(
                        self.RESOURCE_NAME,
                        load_data.INSERT_VIOLATION.format(snapshot_table),
                        formatted_violation)
                    inserted_rows += 1
                except MySQLdb.Error, e:
                    LOGGER.error('Unable to insert violation %s due to %s',
                                 formatted_violation, e)
                    violation_errors.append(formatted_violation)

        return (inserted_rows, violation_errors)

    def get_all_violations(self, timestamp):
        """Get all the violations.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
             A tuple of the violations as dict.
        """
        violations_sql = select_data.VIOLATIONS.format(timestamp)
        rows = self.execute_sql_with_fetch(
            self.RESOURCE_NAME, violations_sql, ())
        return rows


def _format_violation(violation):
    """Format the violation data into a tuple.

    Also flattens the RuleViolation, since it consists of the resource,
    rule, and members that don't meet the rule criteria.

    Various properties of RuleViolation may also have values that exceed the
    declared column length, so truncate as necessary to prevent MySQL errors.

    Args:
        violation: The RuleViolation.

    Yields:
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
