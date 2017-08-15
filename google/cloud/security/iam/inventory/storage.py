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
from sqlalchemy import BigInteger
from sqlalchemy import DateTime
from sqlalchemy import Integer

from sqlalchemy.ext.declarative import declarative_base

from google.cloud.security.inventory2.storage import Storage as BaseStorage

BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024


class InventoryState(object):
    """Possible states for inventory."""

    SUCCESS = "SUCCESS"
    RUNNING = "RUNNING"
    FAILURE = "FAILURE"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    TIMEOUT = "TIMEOUT"
    CREATED = "CREATED"


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

    @classmethod
    def _utcnow(self):
        return datetime.datetime.utcnow()

    def __repr__(self):
        return """<{}(id='{}', version='{}', timestamp='{}')>""".format(
            self.__class__.__name__,
            self.id,
            self.schema_version,
            self.start_time)

    @classmethod
    def create(cls):
        return InventoryIndex(
            start_time=cls._utcnow(),
            status=InventoryState.CREATED,
            schema_version=CURRENT_SCHEMA,
            counter=0)

    def complete(self):
        self.complete_time = InventoryIndex._utcnow()
        self.status = InventoryState.SUCCESS

    def add_warning(self, session, warning):
        """Add a warning to the inventory.

        Args:
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
        """Indicate a broken import."""

        self.state = "BROKEN"
        self.message = message
        session.add(self)
        session.flush()


class GSuiteMembership(BASE):
    """Gsuite membership table."""

    __tablename__ = 'gsuite_inventory'

    index = Column(BigInteger(), primary_key=True)
    member_name = Column(String(1024))
    parents = Column(Text())
    other = Column(Text())


class Inventory(BASE):
    """Resource inventory table."""

    __tablename__ = 'gcp_inventory'

    index = Column(BigInteger(), primary_key=True)
    resource_key = Column(String(1024), primary_key=True)
    resource_type = Column(String(256), primary_key=True)
    resource_data = Column(Text())
    parent_resource_key = Column(String(1024))
    parent_resource_type = Column(String(256))
    iam_policy = Column(Text())
    gcs_policy = Column(Text())
    other = Column(Text())

    @classmethod
    def from_resource(cls, index, resource):
        parent = resource.parent()
        return Inventory(
            index=index.id,
            resource_key=resource.key(),
            resource_type=resource.type(),
            resource_data=json.dumps(resource.data()),
            parent_resource_key=None if not parent else parent.key(),
            parent_resource_type=None if not parent else parent.type(),
            iam_policy=json.dumps(resource.getIamPolicy()),
            gcs_policy=json.dumps(resource.getGCSPolicy()),
            other=None)

    def __repr__(self):
        return """<{}(index='{}', key='{}', type='{}')>""".format(
            self.__class__.__name__,
            self.index,
            self.resource_key,
            self.resource_type)

    def get_key(self):
        return self.resource_key

    def get_type(self):
        return self.resource_type

    def get_parent_key(self):
        return self.parent_resource_key

    def get_parent_type(self):
        return self.parent_resource_type

    def get_data(self):
        return json.loads(self.resource_data)

    def get_other(self):
        return json.loads(self.other)

    def get_iam_policy(self):
        if not self.iam_policy:
            return None
        return json.loads(self.iam_policy)

    def get_gcs_policy(self):
        if not self.gcs_policy:
            return None
        return json.loads(self.gcs_policy)


class BufferedDbWriter(object):
    """Buffered db writing."""

    def __init__(self, session, max_size=1):
        self.session = session
        self.buffer = []
        self.max_size = max_size

    def add(self, obj):
        self.buffer.append(obj)
        if self.buffer >= self.max_size:
            self.flush()

    def flush(self):
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
        """

        try:
            result = cls.get(session, inventory_id)
            session.query(Inventory).filter(
                Inventory.index == inventory_id).delete()
            session.query(GSuiteMembership).filter(
                GSuiteMembership.index == inventory_id).delete()
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
    BASE.metadata.create_all(engine)


class Storage(BaseStorage):
    """Inventory storage used during creation."""

    def __init__(self, session, existing_id=None):
        self.session = session
        self.opened = False
        self.index = None
        self.buffer = BufferedDbWriter(self.session)
        self._existing_id = existing_id

    def _require_opened(self):
        if not self.opened:
            raise Exception('Storage is not opened')

    def _create(self):
        try:
            index = InventoryIndex.create()
            self.session.add(index)
        except Exception:
            self.session.rollback()
            raise
        else:
            return index

    def _open(self, existing_id):
        return (
            self.session.query(InventoryIndex)
            .filter(InventoryIndex.id == existing_id)
            .one())

    def open(self, existing_id=None):
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
        self.session.flush()
        return self.index.id

    def close(self):
        if not self.opened:
            raise Exception('not open')

        try:
            self.buffer.flush()
            self.index.complete()
            self.session.commit()
        except Exception:
            raise
        else:
            self.opened = False

    def write(self, resource):
        self.buffer.add(
            Inventory.from_resource(
                self.index,
                resource))
        self.index.counter += 1

    def read(self, resource_key):
        self.buffer.flush()
        return (
            self.session.query(Inventory)
            .filter(Inventory.index == self.index.id)
            .filter(Inventory.resource_key == resource_key)
            .one())

    def error(self, message):
        self.index.set_error(self.session, message)

    def warning(self, message):
        self.index.add_warning(self.session, message)

    def iter(self,
             type_list=[],
             require_iam_policy=False,
             require_gcs_policy=False):

        base_query = (
            self.session.query(Inventory)
            .filter(Inventory.index == self.index.id))
        if require_iam_policy:
            base_query = base_query.filter(Inventory.iam_policy != 'null')
        if require_gcs_policy:
            base_query = base_query.filter(Inventory.gcs_policy != 'null')

        if type_list:
            for res_type in type_list:
                qry = (base_query
                       .filter(Inventory.resource_type == res_type))
                for resource in qry.yield_per(1024):
                    yield resource
        else:
            for resource in base_query.yield_per(1024):
                yield resource

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, type_p, value, tb):
        self.close()
