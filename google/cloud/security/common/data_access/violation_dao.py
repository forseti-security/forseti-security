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

from collections import namedtuple
import MySQLdb

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access import violation_map as vm
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


class ViolationDao(dao.Dao):
    """Data access object (DAO) for rule violations."""

    def insert_violations(self, violations, resource_name,
                          snapshot_timestamp=None):
        """Import violations into database.

        Args:
            violations: An iterator of RuleViolations.
            resource_name: String that defines a resource
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
                resource_name, snapshot_timestamp)
        except MySQLdb.Error, e:
            raise db_errors.MySQLError(resource_name, e)

        inserted_rows = 0
        violation_errors = []
        for violation in violations:
            violation = Violation(resource_type=violation['resource_type'],
                                  resource_id=violation['resource_id'],
                                  rule_name=violation['rule_name'],
                                  rule_index=violation['rule_index'],
                                  violation_type=violation['violation_type'],
                                  violation_data=violation['violation_data'])
            for formatted_violation in _format_violation(violation,
                                                         resource_name):
                try:
                    self.execute_sql_with_commit(
                        resource_name,
                        vm.VIOLATION_INSERT_MAP[resource_name](snapshot_table),
                        formatted_violation)
                    inserted_rows += 1
                except MySQLdb.Error, e:
                    LOGGER.error('Unable to insert violation %s due to %s',
                                 formatted_violation, e)
                    violation_errors.append(formatted_violation)

        return (inserted_rows, violation_errors)

    def get_all_violations(self, timestamp, resource_name):
        """Get all the violations.

        Args:
            timestamp: The timestamp of the snapshot.

        Returns:
             A tuple of the violations as dict.
        """
        violations_sql = vm.VIOLATION_SELECT_MAP[resource_name](timestamp)
        rows = self.execute_sql_with_fetch(
            resource_name, violations_sql, ())
        return rows


def _format_violation(violation, resource_name):
    """Violation formating stub that uses a map to call the formating
    function for the resource.

    Args:
        violation: An iterator of RuleViolations.
        resource_name: String that defines a resource

    Returns:
        Formatted violations
    """

    formatted_output = vm.VIOLATION_MAP[resource_name](violation)
    return formatted_output

Violation = namedtuple('Violation',
                        ['resource_type', 'resource_id', 'rule_name',
                         'rule_index', 'violation_type', 'violation_data'])
