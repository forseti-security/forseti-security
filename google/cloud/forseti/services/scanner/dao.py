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

""" Database access objects for Forseti Scanner. """

from collections import defaultdict
import hashlib
import json

from sqlalchemy import BigInteger
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import and_
from sqlalchemy import inspect
from sqlalchemy.ext.declarative import declarative_base

from google.cloud.forseti.common.data_access import violation_map as vm
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.index_state import IndexState

LOGGER = logger.get_logger(__name__)
BASE = declarative_base()
CURRENT_SCHEMA = 1
SUCCESS_STATES = [IndexState.SUCCESS, IndexState.PARTIAL_SUCCESS]


class ScannerIndex(BASE):
    """Represents a scanner run."""

    __tablename__ = 'scanner_index'

    id = Column(BigInteger, primary_key=True)
    inventory_index_id = Column(BigInteger)
    created_at_datetime = Column(DateTime())
    completed_at_datetime = Column(DateTime())
    scanner_status = Column(Text())
    schema_version = Column(Integer())
    scanner_index_warnings = Column(Text(16777215))
    scanner_index_errors = Column(Text())
    message = Column(Text())

    def __repr__(self):
        """Object string representation.

        Returns:
            str: String representation of the object.
        """
        return """<{}(id='{}', version='{}', timestamp='{}')>""".format(
            self.__class__.__name__,
            self.id,
            self.schema_version,
            self.created_at_datetime)

    @classmethod
    def create(cls, inv_index_id):
        """Create a new scanner index row.

        Args:
            inv_index_id (str): Id of the inventory index.

        Returns:
            object: ScannerIndex row object.
        """
        utc_now = date_time.get_utc_now_datetime()
        micro_timestamp = date_time.get_utc_now_microtimestamp(utc_now)
        return ScannerIndex(
            id=micro_timestamp,
            inventory_index_id=inv_index_id,
            created_at_datetime=utc_now,
            scanner_status=IndexState.CREATED,
            schema_version=CURRENT_SCHEMA)

    def complete(self, status=IndexState.SUCCESS):
        """Mark the scanner as completed with a final scanner_status.

        Args:
            status (str): Final scanner_status.
        """
        self.completed_at_datetime = date_time.get_utc_now_datetime()
        self.scanner_status = status

    def add_warning(self, session, warning):
        """Add a warning to the scanner.

        Args:
            session (object): session object to work on.
            warning (str): Warning message
        """
        warning_message = '{}\n'.format(warning)
        if not self.scanner_index_warnings:
            self.scanner_index_warnings = warning_message
        else:
            self.scanner_index_warnings += warning_message
        session.add(self)
        session.flush()

    def set_error(self, session, message):
        """Indicate a broken scanner run.

        Args:
            session (object): session object to work on.
            message (str): Error message to set.
        """
        self.scanner_index_errors = message
        session.add(self)
        session.flush()


def get_latest_scanner_index_id(session, inv_index_id, index_state=None):
    """Return last `ScannerIndex` row with the given state or `None`.

    Either return the latest `ScannerIndex` row where the `scanner_status`
    matches the given `index_state` parameter (if passed) or the latest row
    that represents a (partially) successful scanner run.

    Args:
        session (object): session object to work on.
        inv_index_id (str): Id of the inventory index.
        index_state (str): we want the latest `ScannerIndex` with this state

    Returns:
        sqlalchemy_object: the latest `ScannerIndex` row or `None`
    """
    scanner_index = None
    if not index_state:
        scanner_index = (
            session.query(ScannerIndex)
            .filter(and_(
                ScannerIndex.scanner_status.in_(SUCCESS_STATES),
                ScannerIndex.inventory_index_id == inv_index_id))
            .order_by(ScannerIndex.id.desc()).first())
    else:
        scanner_index = (
            session.query(ScannerIndex)
            .filter(and_(
                ScannerIndex.scanner_status == index_state,
                ScannerIndex.inventory_index_id == inv_index_id))
            .order_by(ScannerIndex.created_at_datetime.desc()).first())
    return scanner_index.id if scanner_index else None


class Violation(BASE):
    """Row entry for a violation."""

    __tablename__ = 'violations'

    id = Column(Integer, primary_key=True)
    created_at_datetime = Column(DateTime())
    full_name = Column(String(1024))
    resource_data = Column(Text(16777215))
    resource_name = Column(String(256), default='')
    resource_id = Column(String(256), nullable=False)
    resource_type = Column(String(256), nullable=False)
    rule_index = Column(Integer, default=0)
    rule_name = Column(String(256))
    scanner_index_id = Column(BigInteger)
    violation_data = Column(Text)
    violation_hash = Column(String(256))
    violation_type = Column(String(256), nullable=False)

    def __repr__(self):
        """String representation.

        Returns:
            str: string representation of the Violation row entry.
        """
        string = ('<Violation(violation_type={}, resource_type={} '
                  'rule_name={})>')
        return string.format(
            self.violation_type, self.resource_type, self.rule_name)

    @staticmethod
    def get_schema_update_actions():
        """Maintain all the schema changes for this table.

        Returns:
            dict: A mapping of Action: Column.
        """
        columns_to_create = [Column('resource_name',
                                    String(256),
                                    default='')]

        schema_update_actions = {'CREATE': columns_to_create}
        return schema_update_actions


class ViolationAccess(object):
    """Facade for violations, implement APIs against violations table."""

    def __init__(self, session):
        """Constructor for the Violation Access.

        Args:
            session (Session): SQLAlchemy session object.
        """
        self.session = session

    def create(self, violations, scanner_index_id):
        """Save violations to the db table.

        Args:
            violations (list): A list of violations.
            scanner_index_id (int): id of the `ScannerIndex` row for this
                scanner run.
        """
        created_at_datetime = date_time.get_utc_now_datetime()
        for violation in violations:
            violation_hash = _create_violation_hash(
                violation.get('full_name', ''),
                violation.get('resource_data', ''),
                violation.get('violation_data', ''),
            )

            violation = Violation(
                created_at_datetime=created_at_datetime,
                full_name=violation.get('full_name'),
                resource_data=violation.get('resource_data'),
                resource_name=violation.get('resource_name'),
                resource_id=violation.get('resource_id'),
                resource_type=violation.get('resource_type'),
                rule_index=violation.get('rule_index'),
                rule_name=violation.get('rule_name'),
                scanner_index_id=scanner_index_id,
                violation_data=json.dumps(
                    violation.get('violation_data'), sort_keys=True),
                violation_hash=violation_hash,
                violation_type=violation.get('violation_type')
            )
            self.session.add(violation)

    def list(self, inv_index_id=None, scanner_index_id=None):
        """List all violations from the db table.

        If
            * neither index is passed we return all violations.
            * the `inv_index_id` is passed the violations from all scanner
              runs for that inventory index will be returned.
            * the `scanner_index_id` is passed the violations from that
              specific scanner run will be returned.

        NOTA BENE: do *NOT* call this method with both indices!

        Args:
            inv_index_id (str): Id of the inventory index.
            scanner_index_id (int): Id of the scanner index.

        Returns:
            list: List of Violation row entry objects.

        Raises:
            ValueError: if called with both the inventory and the scanner index
        """
        if not (inv_index_id or scanner_index_id):
            return self.session.query(Violation).all()

        if (inv_index_id and scanner_index_id):
            raise ValueError(
                'Please call list() with the inventory index XOR the scanner '
                'index, not both.')

        results = []
        if inv_index_id:
            results = (
                self.session.query(Violation, ScannerIndex)
                .filter(and_(
                    ScannerIndex.scanner_status.in_(SUCCESS_STATES),
                    ScannerIndex.inventory_index_id == inv_index_id))
                .filter(Violation.scanner_index_id == ScannerIndex.id)
                .all())
        if scanner_index_id:
            results = (
                self.session.query(Violation, ScannerIndex)
                .filter(and_(
                    ScannerIndex.scanner_status.in_(SUCCESS_STATES),
                    ScannerIndex.id == scanner_index_id))
                .filter(Violation.scanner_index_id == ScannerIndex.id)
                .all())

        violations = []
        for violation, _ in results:
            violations.append(violation)
        return violations


# pylint: disable=invalid-name
def convert_sqlalchemy_object_to_dict(sqlalchemy_obj):
    """Convert a sqlalchemy row/record object to a dictionary.

    Args:
        sqlalchemy_obj (sqlalchemy_object): A sqlalchemy row/record object

    Returns:
        dict: A dict of sqlalchemy object's attributes.
    """

    return {c.key: getattr(sqlalchemy_obj, c.key)
            for c in inspect(sqlalchemy_obj).mapper.column_attrs}


def map_by_resource(violation_rows):
    """Create a map of violation types to violations of that resource.

    Args:
        violation_rows (list): A list of dict of violation data.

    Returns:
        dict: A dict of violation types mapped to the list of corresponding
            violation types, i.e. { resource => [violation_data...] }.
    """
    # The defaultdict makes it easy to add a value to a key without having
    # to check if the key exists.
    v_by_type = defaultdict(list)

    for v_data in violation_rows:

        try:
            v_data['violation_data'] = json.loads(v_data['violation_data'])
        except ValueError:
            LOGGER.warn('Invalid violation data, unable to parse json for %s',
                        v_data['violation_data'])

        # resource_data can be regular python string
        try:
            v_data['resource_data'] = json.loads(v_data['resource_data'])
        except ValueError:
            v_data['resource_data'] = json.loads(
                json.dumps(v_data['resource_data']))

        v_resource = vm.VIOLATION_RESOURCES.get(v_data['violation_type'])
        if v_resource:
            v_by_type[v_resource].append(v_data)

    return dict(v_by_type)


def _create_violation_hash(violation_full_name, resource_data, violation_data):
    """Create a hash of violation data.

    Args:
        violation_full_name (str): The full name of the violation.
        resource_data (str): The inventory data.
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
    except ValueError:
        LOGGER.exception('Cannot create hash for a violation with algorithm: '
                         '%s', algorithm)
        return ''

    try:
        # Group resources do not have full name.  Issue #1072
        violation_hash.update(
            json.dumps(violation_full_name) +
            json.dumps(resource_data, sort_keys=True) +
            json.dumps(violation_data, sort_keys=True)
        )
    except TypeError:
        LOGGER.exception('Cannot create hash for a violation: %s',
                         violation_full_name)
        return ''

    return violation_hash.hexdigest()


def initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """
    # Create tables if not exists.
    BASE.metadata.create_all(engine)
