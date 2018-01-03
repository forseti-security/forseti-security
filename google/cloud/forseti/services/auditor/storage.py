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

"""Auditor storage implementation."""

import enum
import json

from datetime import datetime

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import ForeignKeyConstraint
from sqlalchemy import Integer
from sqlalchemy import JSON
from sqlalchemy import Text
from sqlalchemy import and_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import aliased

from google.cloud.forseti.services.inventory.storage import BufferedDbWriter
from google.cloud.forseti.services.inventory.base.storage \
    import Storage as BaseStorage

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc,too-many-instance-attributes

BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024


class AuditStatus(enum.Enum):
    """Possible states for audit."""

    UNSPECIFIED = 0
    RUNNING = 1
    ERROR = 2
    SUCCESS = 3


class Audit(BASE):
    """Represents an Audit."""

    __tablename__ = 'audit'

    id = Column(Integer(), primary_key=True, autoincrement=True)
    start_time = Column(DateTime(), default=datetime.utcnow)
    end_time = Column(DateTime(), onupdate=datetime.utcnow)
    status = Column(Enum(AuditStatus))
    model = Column(JSON())
    messages = Column(Text())
    schema_version = Column(Integer())

    def __repr__(self):
        """Object string representation.

        Returns:
            str: String representation of the object.
        """

        return '<{}(id="{}", version="{}", timestamp="{}")>'.format(
            self.__class__.__name__,
            self.id,
            self.schema_version,
            self.start_time)

    @classmethod
    def create(cls):
        """Create a new audit row.

        Returns:
            object: Audit row object.
        """

        return Audit(
            status=AuditStatus.RUNNING,
            schema_version=CURRENT_SCHEMA,
            model=None)

    def complete(self, status=AuditStatus.SUCCESS):
        """Mark the audit as completed with a final status.

        Args:
            status (str): Final status.
        """

        self.status = status

    def add_warning(self, session, messages):
        """Add a warning to the audit.

        Args:
            session (object): session object to work on.
            messages (str): Warning message
        """

        warning_message = '{}\n'.format(messages)
        if not self.messages:
            self.messages = warning_message
        else:
            self.messages += warning_message
        session.add(self)
        session.flush()

    def set_error(self, session, messages):
        """Indicate a broken import.

        Args:
            session (object): session object to work on.
            message (str): Messages to set.
        """

        self.messages = messages
        session.add(self)
        session.flush()


class Rule(BASE):
    """Represent a Rule."""

    __tablename__ = 'rule'

    id = Column(Integer(), primary_key=True, autoincrement=True)
    rule_name = Column(Text())
    rule_hash = Column(Text())
    properties = Column(JSON())


class AuditRule(BASE):
    """Represent an AuditRule."""

    __tablename__ = 'audit_rule'
    __table_args__ = (ForeignKeyConstraint(['audit_id'], ['audit.id']),
                      ForeignKeyConstraint(['rule_id'], ['rule.id']))

    id = Column(Integer(), primary_key=True, autoincrement=True)
    audit_id = Column(Integer(), nullable=False)
    rule_id = Column(Integer(), nullable=False)


# TODO: don't know where this should be defined --
# creating it here for now
class RuleResultStatus(enum.Enum):
    """RuleResult statuses."""

    UNSPECIFIED = 0;
    ACTIVE = 1;
    RESOLVED = 2;
    IGNORED = 3;


class RuleResult(BASE):
    """Represent a RuleResult."""

    __tablename__ = 'rule_result'
    __table_args__ = (ForeignKeyConstraint(['audit_id'], ['audit.id']),
                      ForeignKeyConstraint(['rule_id'], ['rule.id']))

    id = Column(Integer(), primary_key=True, autoincrement=True)
    audit_id = Column(Integer(), nullable=False)
    rule_id = Column(Integer(), nullable=False)
    resource_name = Column(Text(), nullable=False)
    current_state = Column(JSON())
    expected_state = Column(JSON())
    model_handle = Column(Text(), nullable=False)
    resource_owners = Column(JSON())
    info = Column(Text())
    status = Column(Enum(RuleResultStatus))
    create_time = Column(DateTime(), default=datetime.utcnow)
    modified_time = Column(DateTime(), onupdate=datetime.utcnow)
    recommended_actions = Column(Text())


class DataAccess(object):
    """Access to audit for services."""

    @classmethod
    def delete(cls, session, audit_id):
        """Delete an audit entry by id.

        Args:
            session (object): Database session.
            audit_id (int): Id specifying which audit to delete.

        Raises:
            Exception: Reraises any exception.
        """

        try:
            result = cls.get(session, audit_id)
            session.query(Audit).filter(
                Audit.id == audit_id).delete()
            session.commit()
            return result
        except Exception:
            session.rollback()
            raise

    @classmethod
    def list(cls, session):
        """List all Audit entries.

        Args:
            session (object): Database session

        Yields:
            Audit: Generates each row
        """

        for row in session.query(Audit).yield_per(PER_YIELD):
            session.expunge(row)
            yield row

    @classmethod
    def get(cls, session, audit_id):
        """Get an audit entry by id.

        Args:
            session (object): Database session
            audit_id (int): Audit id

        Returns:
            Audit: Entry corresponding the id
        """

        result = (
            session.query(Audit)
            .filter(Audit.id == audit_id)
            .one())
        session.expunge(result)
        return result


def initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """

    BASE.metadata.create_all(engine)


class Storage(BaseStorage):
    """Inventory storage used during creation."""

    def __init__(self, session, existing_id=None, readonly=False):
        self.session = session
        self.opened = False
        self.index = None
        self.buffer = BufferedDbWriter(self.session)
        self._existing_id = existing_id
        self.session_completed = False
        self.readonly = readonly

    def _require_opened(self):
        """Make sure the storage is in 'open' state.

        Raises:
            Exception: If storage is not opened.
        """

        if not self.opened:
            raise Exception('Storage is not opened')

    def _create(self):
        """Create a new inventory.

        Returns:
            int: Index number of the created inventory.

        Raises:
            Exception: Reraises any exception.
        """

        try:
            index = InventoryIndex.create()
            self.session.add(index)
        except Exception:
            self.session.rollback()
            raise
        else:
            return index

    def _open(self, existing_id):
        """Open an existing inventory.

        Returns:
            object: The inventory db row.
        """

        return (
            self.session.query(InventoryIndex)
            .filter(InventoryIndex.id == existing_id)
            .filter(InventoryIndex.status.in_(
                [InventoryState.SUCCESS, InventoryState.PARTIAL_SUCCESS]))
            .one())

    def _get_resource_rows(self, key):
        """ Get the rows in the database for a certain resource

        Args:
            key (str): The key of the resource

        Returns:
            object: The inventory db rows of the resource,
            IAM policy and GCS policy.

        Raises:
            Exception: if there is no such row or more than one.
        """

        qry = (
            self.session.query(Inventory)
            .filter(Inventory.index == self.index.id)
            .filter(Inventory.key == key))
        rows = qry.all()

        if not rows:
            raise Exception("resource {} not found in the table".format(key))
        else:
            return rows

    def open(self, handle=None):
        """Open the storage, potentially create a new index.

        Args:
            handle (int): If None, create a new index instead
                          of opening an existing one.

        Returns:
            int: Index number of the opened or created inventory.

        Raises:
            Exception: if open was called more than once
        """

        existing_id = handle
        if self.opened:
            raise Exception('open called before')

        # existing_id in open overrides potential constructor given id
        existing_id = existing_id if existing_id else self._existing_id

        # Should we create a new entry or are we opening an existing one?
        if existing_id:
            self.index = self._open(existing_id)
        else:
            self.index = self._create()

        self.opened = True
        self.session.commit()
        if not self.readonly:
            self.session.begin_nested()
        return self.index.id

    def rollback(self):
        """Roll back the stored inventory, but keep the index entry."""

        try:
            self.buffer.flush()
            self.session.rollback()
            self.index.complete(status=InventoryState.FAILURE)
            self.session.commit()
        finally:
            self.session_completed = True

    def commit(self):
        """Commit the stored inventory."""

        try:
            self.buffer.flush()
            self.session.commit()
            self.index.complete()
            self.session.commit()
        finally:
            self.session_completed = True

    def close(self):
        """Close the storage.

        Raises:
            Exception: If the storage was not opened before or
                       if the storage is writeable but neither
                       rollback nor commit has been called.
        """

        if not self.opened:
            raise Exception('not open')

        if not self.readonly and not self.session_completed:
            raise Exception('Need to perform commit or rollback before close')

        self.opened = False

    def write(self, resource):
        """Write a resource to the storage and updates its row

        Args:
            resource (object): Resource object to store in db.

        Raises:
            Exception: If storage was opened readonly.
        """

        if self.readonly:
            raise Exception('Opened storage readonly')

        rows = Inventory.from_resource(self.index, resource)
        for row in rows:
            self.buffer.add(row)

        self.index.counter += len(rows)

    def update(self, resource):
        """Update a resource in the storage.

        Args:
            resource (object): Resource object to store in db.

        Raises:
            Exception: If storage was opened readonly.
        """

        if self.readonly:
            raise Exception('Opened storage readonly')

        self.buffer.flush()

        try:
            new_rows = Inventory.from_resource(self.index, resource)
            old_rows = self._get_resource_rows(resource.key())

            new_dict = {row.type_class : row for row in new_rows}
            old_dict = {row.type_class : row for row in old_rows}

            for type_class in InventoryTypeClass.SUPPORTED_TYPECLASS:
                if type_class in new_dict:
                    if type_class in old_dict:
                        old_dict[type_class].copy_inplace(new_dict[type_class])
                    else:
                        self.session.add(new_dict[type_class])
            self.session.commit()
        except Exception as e:
            raise Exception('Resource Update Unsuccessful: {}'.format(e))

    def error(self, message):
        """Store a fatal error in storage. This will help debug problems.

        Args:
            message (str): Error message describing the problem.

        Raises:
            Exception: If the storage was opened readonly.
        """

        if self.readonly:
            raise Exception('Opened storage readonly')
        self.index.set_error(self.session, message)

    def warning(self, message):
        """Store a fatal error in storage. This will help debug problems.

        Args:
            message (str): Error message describing the problem.

        Raises:
            Exception: If the storage was opened readonly.
        """

        if self.readonly:
            raise Exception('Opened storage readonly')
        self.index.add_warning(self.session, message)

    def iter(self,
             type_list=None,
             fetch_iam_policy=False,
             fetch_gcs_policy=False,
             fetch_dataset_policy=False,
             fetch_billing_info=False,
             fetch_enabled_apis=False,
             with_parent=False):
        """Iterate the objects in the storage.

        Args:
            type_list (list): List of types to iterate over, or [] for all.
            fetch_iam_policy (bool): Yield iam policies.
            fetch_gcs_policy (bool): Yield gcs policies.
            fetch_dataset_policy (bool): Yield dataset policies.
            fetch_billing_info (bool): Yield project billing info.
            fetch_enabled_apis (bool): Yield project enabled APIs info.
            with_parent (bool): Join parent with results, yield tuples.

        Yields:
            object: Single row object or child/parent if 'with_parent' is set.
        """

        filters = []
        filters.append(Inventory.index == self.index.id)

        if fetch_iam_policy:
            filters.append(
                Inventory.type_class == InventoryTypeClass.IAM_POLICY)

        elif fetch_gcs_policy:
            filters.append(
                Inventory.type_class == InventoryTypeClass.GCS_POLICY)

        elif fetch_dataset_policy:
            filters.append(
                Inventory.type_class == InventoryTypeClass.DATASET_POLICY)

        elif fetch_billing_info:
            filters.append(
                Inventory.type_class == InventoryTypeClass.BILLING_INFO)

        elif fetch_enabled_apis:
            filters.append(
                Inventory.type_class == InventoryTypeClass.ENABLED_APIS)

        else:
            filters.append(
                Inventory.type_class == InventoryTypeClass.RESOURCE)

        if type_list:
            filters.append(Inventory.type.in_(type_list))

        if with_parent:
            parent_inventory = aliased(Inventory)
            p_key = parent_inventory.key
            p_type = parent_inventory.type
            base_query = (
                self.session.query(Inventory, parent_inventory)
                .filter(
                    and_(
                        Inventory.parent_key == p_key,
                        Inventory.parent_type == p_type,
                        parent_inventory.index == self.index.id)))
        else:
            base_query = self.session.query(Inventory)

        for qry_filter in filters:
            base_query = base_query.filter(qry_filter)

        base_query = base_query.order_by(Inventory.order.asc())

        for row in base_query.yield_per(PER_YIELD):
            yield row

    def __enter__(self):
        """To support with statement for auto closing."""

        self.open()
        return self

    def __exit__(self, type_p, value, traceback):
        """To support with statement for auto closing.

        Args:
            type_p (object): Unused.
            value (object): Unused.
            traceback (object): Unused.
        """

        self.close()
