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

""" Inventory storage implementation. """

import datetime
import json

from sqlalchemy import Column
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import and_
from sqlalchemy.orm import aliased


from sqlalchemy.ext.declarative import declarative_base
from google.cloud.security.iam.inventory.inventory2.storage import \
    Storage as BaseStorage

# TODO: Remove this when time allows
# pylint: disable=missing-type-doc,missing-return-type-doc,missing-return-doc
# pylint: disable=missing-param-doc

BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024


class InventoryState(object):
    """Possible states for inventory."""

    SUCCESS = 'SUCCESS'
    RUNNING = 'RUNNING'
    FAILURE = 'FAILURE'
    PARTIAL_SUCCESS = 'PARTIAL_SUCCESS'
    TIMEOUT = 'TIMEOUT'
    CREATED = 'CREATED'


class InventoryTypeClass(object):
    """Inventory Type Classes."""

    RESOURCE = 'resource'
    IAM_POLICY = 'iam_policy'
    GCS_POLICY = 'gcs_policy'


class InventoryIndex(BASE):
    """Represents a GCP inventory."""

    __tablename__ = 'inventory_index'

    id = Column(Integer(), primary_key=True, autoincrement=True)
    start_time = Column(DateTime())
    complete_time = Column(DateTime())
    status = Column(Text())
    schema_version = Column(Integer())
    progress = Column(Text())
    counter = Column(Integer())
    warnings = Column(Text())
    errors = Column(Text())
    message = Column(Text())

    @classmethod
    def _utcnow(cls):
        """Return current time in utc.

        Returns:
            object: UTC now time object.
        """

        return datetime.datetime.utcnow()

    def __repr__(self):
        """Object string representation.

        Returns:
            str: String representation of the object.
        """

        return """<{}(id='{}', version='{}', timestamp='{}')>""".format(
            self.__class__.__name__,
            self.id,
            self.schema_version,
            self.start_time)

    @classmethod
    def create(cls):
        """Create a new inventory index row.

        Returns:
            object: InventoryIndex row object.
        """

        return InventoryIndex(
            start_time=cls._utcnow(),
            complete_time=datetime.datetime.utcfromtimestamp(0),
            status=InventoryState.CREATED,
            schema_version=CURRENT_SCHEMA,
            counter=0)

    def complete(self, status=InventoryState.SUCCESS):
        """Mark the inventory as completed with a final status.

        Args:
            status (str): Final status.
        """

        self.complete_time = InventoryIndex._utcnow()
        self.status = status

    def add_warning(self, session, warning):
        """Add a warning to the inventory.

        Args:
            session (object): session object to work on.
            warning (str): Warning message
        """

        warning_message = '{}\n'.format(warning)
        if not self.warnings:
            self.warnings = warning_message
        else:
            self.warnings += warning_message
        session.add(self)
        session.flush()

    def set_error(self, session, message):
        """Indicate a broken import.

        Args:
            session (object): session object to work on.
            message (str): Error message to set.
        """

        self.message = message
        session.add(self)
        session.flush()


class Inventory(BASE):
    """Resource inventory table."""

    __tablename__ = 'gcp_inventory'

    # Order is used to resemble the order of insert for a given inventory
    order = Column(Integer, primary_key=True, autoincrement=True)
    index = Column(Integer)
    type_class = Column(String(128))
    key = Column(String(2048))
    type = Column(String(256))
    data = Column(Text())
    parent_key = Column(String(2048))
    parent_type = Column(String(256))
    other = Column(Text())
    error = Column(Text())

    @classmethod
    def from_resource(cls, index, resource):
        """Creates a database row object from a crawled resource.

        Args:
            index (int): Inventory index number to associate.
            resource (object): Crawled resource.

        Returns:
            object: database row object.
        """

        parent = resource.parent()
        iam_policy = resource.getIamPolicy()
        gcs_policy = resource.getGCSPolicy()

        rows = []
        rows.append(
            Inventory(
                index=index.id,
                type_class=InventoryTypeClass.RESOURCE,
                key=resource.key(),
                type=resource.type(),
                data=json.dumps(resource.data()),
                parent_key=None if not parent else parent.key(),
                parent_type=None if not parent else parent.type(),
                other=None,
                error=None))

        if iam_policy:
            rows.append(
                Inventory(
                    index=index.id,
                    type_class=InventoryTypeClass.IAM_POLICY,
                    key=resource.key(),
                    type=resource.type(),
                    data=json.dumps(iam_policy),
                    parent_key=resource.key(),
                    parent_type=resource.type(),
                    other=None,
                    error=None))

        if gcs_policy:
            rows.append(
                Inventory(
                    index=index.id,
                    type_class=InventoryTypeClass.GCS_POLICY,
                    key=resource.key(),
                    type=resource.type(),
                    data=json.dumps(gcs_policy),
                    parent_key=resource.key(),
                    parent_type=resource.type(),
                    other=None,
                    error=None))
        return rows

    def __repr__(self):
        """String representation of the database row object."""

        return """<{}(index='{}', key='{}', type='{}')>""".format(
            self.__class__.__name__,
            self.index,
            self.key,
            self.type)

    def get_key(self):
        """Get the row's resource key.

        Returns:
            str: resource key.
        """

        return self.key

    def get_type(self):
        """Get the row's resource type.

        Returns:
            str: resource type.
        """

        return self.type

    def get_parent_key(self):
        """Get the row's parent key.

        Returns:
            str: parent key.
        """

        return self.parent_key

    def get_parent_type(self):
        """Get the row's parent type.

        Returns:
            str: parent type.
        """

        return self.parent_type

    def get_data(self):
        """Get the row's raw data.

        Returns:
            dict: row's raw data.
        """

        return json.loads(self.data)

    def get_other(self):
        """Get the row's other data.

        Returns:
            dict: row's other data.
        """

        return json.loads(self.other)

    def get_error(self):
        """Get the row's error data.

        Returns:
            str: row's error data.
        """

        return self.error


class BufferedDbWriter(object):
    """Buffered db writing."""

    def __init__(self, session, max_size=1024):
        self.session = session
        self.buffer = []
        self.max_size = max_size

    def add(self, obj):
        """Add an object to the buffer to write to db.

        Args:
            obj (object): Object to write to db.
        """

        self.buffer.append(obj)
        if self.buffer >= self.max_size:
            self.flush()

    def flush(self):
        """Flush all pending objects to the database."""

        self.session.add_all(self.buffer)
        self.session.flush()
        self.buffer = []


class DataAccess(object):
    """Access to inventory for services."""

    @classmethod
    def delete(cls, session, inventory_id):
        """Delete an inventory index entry by id.

        Args:
            session (object): Database session.
            inventory_id (int): Id specifying which inventory to delete.

        Raises:
            Exception: Reraises any exception.
        """

        try:
            result = cls.get(session, inventory_id)
            session.query(Inventory).filter(
                Inventory.index == inventory_id).delete()
            session.query(InventoryIndex).filter(
                InventoryIndex.id == inventory_id).delete()
            session.commit()
            return result
        except Exception:
            session.rollback()
            raise

    @classmethod
    def list(cls, session):
        """List all inventory index entries.

        Args:
            session (object): Database session

        Yields:
            InventoryIndex: Generates each row
        """

        for row in session.query(InventoryIndex).yield_per(PER_YIELD):
            session.expunge(row)
            yield row

    @classmethod
    def get(cls, session, inventory_id):
        """Get an inventory index entry by id.

        Args:
            session (object): Database session
            inventory_id (int): Inventory id

        Returns:
            InventoryIndex: Entry corresponding the id
        """

        result = (
            session.query(InventoryIndex)
            .filter(InventoryIndex.id == inventory_id)
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
        """Write a resource to the storage.

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

    def read(self, key):
        """Read a resource from the storage.

        Args:
            key (str): Key of the object to read.

        Returns:
            object: Row object read from database.
        """

        self.buffer.flush()
        return (
            self.session.query(Inventory)
            .filter(Inventory.index == self.index.id)
            .filter(Inventory.key == key)
            .one())

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
             with_parent=False):
        """Iterate the objects in the storage.

        Args:
            type_list (list): List of types to iterate over, or [] for all.
            fetch_iam_policy (bool): Yield iam policies.
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
