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

"""Provides the data access object (DAO) for Organizations."""

from datetime import datetime
import hashlib
import json

from collections import defaultdict
from collections import namedtuple

import MySQLdb

from google.cloud.security.common.data_access import dao
from google.cloud.security.common.data_access import errors as db_errors
from google.cloud.security.common.data_access import violation_map as vm
from google.cloud.security.common.data_access.sql_queries import load_data
from google.cloud.security.common.data_access.sql_queries import select_data
from google.cloud.security.common.util import log_util


LOGGER = log_util.get_logger(__name__)


class ViolationDao(dao.Dao):
    """Data access object (DAO) for rule violations."""

    violation_attribute_list = [
        'violation_hash', 'resource_type', 'resource_id', 'rule_name',
        'rule_index', 'violation_type', 'violation_data', 'created_at_datetime']
    frozen_violation_attribute_list = frozenset(violation_attribute_list)
    Violation = namedtuple('Violation', frozen_violation_attribute_list)

    def insert_violations(self, violations,
                          snapshot_timestamp=None):
        """Import violations into database.

        Args:
            violations (iterator): An iterator of RuleViolations.
            snapshot_timestamp (str): The snapshot timestamp to associate
                these violations with.

        Returns:
            tuple: A tuple of (int, list) containing the count of inserted
                rows and a list of violations that encountered an error during
                insert.

        Raise:
            MySQLError: is raised when the snapshot table can not be created.
        """

        resource_name = 'violations'

        try:
            # Make sure to have a reasonable timestamp to use.
            if not snapshot_timestamp:
                snapshot_timestamp = self.get_latest_snapshot_timestamp(
                    ('PARTIAL_SUCCESS', 'SUCCESS'))

            # Create the violations snapshot table.
            snapshot_table = self.create_snapshot_table(
                resource_name, snapshot_timestamp)
        # TODO: Remove this exception handling by moving the check for
        # violations table outside of the scanners.
        except MySQLdb.OperationalError, e:
            if e[0] == 1050:
                LOGGER.debug('Violations table already exists: %s', e)
                snapshot_table = self._create_snapshot_table_name(
                    resource_name, snapshot_timestamp)
            else:
                raise db_errors.MySQLError(resource_name, e)
        except MySQLdb.Error, e:
            raise db_errors.MySQLError(resource_name, e)

        created_at = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        inserted_rows = 0
        violation_errors = []
        for violation in violations:
            violation = self.Violation(
                violation_hash=_create_violation_hash(
                    violation['resource_id'], violation['violation_data']),
                resource_type=violation['resource_type'],
                resource_id=violation['resource_id'],
                rule_name=violation['rule_name'],
                rule_index=violation['rule_index'],
                violation_type=violation['violation_type'],
                violation_data=violation['violation_data'],
                created_at_datetime=created_at)
            for formatted_violation in _format_violation(violation,
                                                         resource_name):
                try:
                    self.execute_sql_with_commit(
                        resource_name,
                        load_data.INSERT_VIOLATION.format(snapshot_table),
                        formatted_violation)
                    inserted_rows += 1
                except MySQLdb.Error, e:
                    LOGGER.error('Unable to insert violation %s due to %s',
                                 formatted_violation, e)
                    violation_errors.append(formatted_violation)

        return (inserted_rows, violation_errors)

    def get_all_violations(self, timestamp, violation_type=None):
        """Get all the violations.

        Args:
            timestamp (str): The timestamp of the snapshot.
            violation_type (str): The violation type.

        Returns:
            list: A list of dict of the violations data.
        """
        if not violation_type:
            resource_name = 'all_violations'
            query = select_data.SELECT_ALL_VIOLATIONS
            params = ()
        else:
            resource_name = violation_type
            query = select_data.SELECT_VIOLATIONS_BY_TYPE
            params = (violation_type,)

        violations_sql = query.format(timestamp)
        rows = self.execute_sql_with_fetch(
            resource_name, violations_sql, params)
        return rows


def _format_violation(violation, resource_name):
    """Violation formating stub that uses a map to call the formating
    function for the resource.

    Args:
        violation (iterator): An iterator of RuleViolations.
        resource_name (str): String that defines a resource.

    Returns:
        tuple: A tuple of formatted violation.
    """
    formatted_output = vm.VIOLATION_MAP[resource_name](violation)
    return formatted_output


def map_by_resource(violation_rows):
    """Create a map of violation types to violations of that resource.

    Args:
        violation_rows (list): A list of dict of violation data.

    Returns:
        dict: A dict of violation types mapped to the list of corresponding
            violation types, i.e. { resource => [violation_data...] }.
    """
    v_by_type = defaultdict(list)

    for v_data in violation_rows:
        try:
            v_data['violation_data'] = json.loads(v_data['violation_data'])
        except ValueError:
            LOGGER.warn('Invalid violation data, unable to parse json for %s',
                        v_data['violation_data'])

        v_resource = vm.VIOLATION_RESOURCES.get(v_data['violation_type'])
        if v_resource:
            v_by_type[v_resource].append(v_data)

    return dict(v_by_type)

def _create_violation_hash(resource_id, violation_data):
    """Create a hash of violation data.

    Args:
        resource_id (str): The id of the resource.
        violation_data (dict): A violation.

    Returns:
        str: The resulting hex digest or '' if we can't successfully create
        a hash.
    """

    # TODO: Intelligently choose from hashlib.algorithms_guaranteed if our
    # desired one is not available.
    algorithm = 'sha512'

    try:
        violation_hash = hashlib.new(algorithm)
    except ValueError as e:
        LOGGER.error('Cannot create hash for a violation with algorithm: '
                     '%s\n%s', algorithm, e)
        return ''

    try:
        violation_hash.update(
            str(resource_id) +
            json.dumps(violation_data, sort_keys=True)
        )
    except TypeError as e:
        LOGGER.error('Cannot create hash for a violation: %s\n%s',
                     resource_id, e)
        return ''

    return violation_hash.hexdigest()
