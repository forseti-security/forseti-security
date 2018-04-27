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

""" Inventory storage implementation. """

import json

from sqlalchemy import Column
from sqlalchemy import Text
from sqlalchemy import String
from sqlalchemy import DateTime
from sqlalchemy import Integer
from sqlalchemy import and_
from sqlalchemy import func
from sqlalchemy import or_
from sqlalchemy import exists
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import aliased

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.common.util.index_state import IndexState
# pylint: disable=line-too-long
from google.cloud.forseti.services.inventory.base.storage import Storage as BaseStorage
# pylint: enable=line-too-long

# pylint: disable=too-many-instance-attributes

LOGGER = logger.get_logger(__name__)
BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024


class InventoryTypeClass(object):
    """Inventory Type Classes."""

    RESOURCE = 'resource'
    IAM_POLICY = 'iam_policy'
    GCS_POLICY = 'gcs_policy'
    DATASET_POLICY = 'dataset_policy'
    BILLING_INFO = 'billing_info'
    ENABLED_APIS = 'enabled_apis'
    SERVICE_CONFIG = 'kubernetes_service_config'

    SUPPORTED_TYPECLASS = frozenset(
        [RESOURCE, IAM_POLICY, GCS_POLICY, DATASET_POLICY, BILLING_INFO,
         ENABLED_APIS, SERVICE_CONFIG])


class InventoryIndex(BASE):
    """Represents a GCP inventory."""

    __tablename__ = 'inventory_index'

    id = Column(String(256), primary_key=True)
    created_at_datetime = Column(DateTime())
    completed_at_datetime = Column(DateTime())
    inventory_status = Column(Text())
    schema_version = Column(Integer())
    progress = Column(Text())
    counter = Column(Integer())
    inventory_index_warnings = Column(Text(16777215))
    inventory_index_errors = Column(Text())
    message = Column(Text())

    @classmethod
    def _utcnow(cls):
        """Return current time in utc.

        Returns:
            object: UTC now time object.
        """
        return date_time.get_utc_now_datetime()

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
    def create(cls):
        """Create a new inventory index row.

        Returns:
            object: InventoryIndex row object.
        """
        created_at_datetime = cls._utcnow()
        return InventoryIndex(
            id=created_at_datetime.strftime(string_formats.TIMESTAMP_MICROS),
            created_at_datetime=created_at_datetime,
            completed_at_datetime=date_time.get_utc_now_datetime(),
            inventory_status=IndexState.CREATED,
            schema_version=CURRENT_SCHEMA,
            counter=0)

    def complete(self, status=IndexState.SUCCESS):
        """Mark the inventory as completed with a final inventory_status.

        Args:
            status (str): Final inventory_status.
        """
        self.completed_at_datetime = InventoryIndex._utcnow()
        self.inventory_status = status

    def add_warning(self, session, warning):
        """Add a warning to the inventory.

        Args:
            session (object): session object to work on.
            warning (str): Warning message
        """
        warning_message = '{}\n'.format(warning)
        if not self.inventory_index_warnings:
            self.inventory_index_warnings = warning_message
        else:
            self.inventory_index_warnings += warning_message
        session.add(self)
        session.flush()

    def set_error(self, session, message):
        """Indicate a broken import.

        Args:
            session (object): session object to work on.
            message (str): Error message to set.
        """
        self.inventory_index_errors = message
        session.add(self)
        session.flush()

    def get_summary(self, session):
        """Generate/return an inventory summary for this inventory index.

        Args:
            session (object): session object to work on.

        Returns:
            dict: a (resource type -> count) dictionary
        """
        resource_type = Inventory.resource_type
        return dict(
            session.query(resource_type, func.count(resource_type))
            .filter(Inventory.inventory_index_id == self.id)
            .group_by(resource_type).all())


class Inventory(BASE):
    """Resource inventory table."""

    __tablename__ = 'gcp_inventory'

    id = Column(Integer, primary_key=True, autoincrement=True)
    inventory_index_id = Column(String(256))
    resource_type = Column(Text)
    category = Column(Text)
    resource_id = Column(Text)
    resource_data = Column(Text(16777215))
    parent_resource_type = Column(Text)
    parent_resource_id = Column(Text)
    other = Column(Text)
    inventory_errors = Column(Text)

    @classmethod
    def from_resource(cls, index, resource):
        """Creates a database row object from a crawled resource.

        Args:
            index (object): InventoryIndex to associate.
            resource (object): Crawled resource.

        Returns:
            object: database row object.
        """

        parent = resource.parent()
        iam_policy = resource.get_iam_policy()
        gcs_policy = resource.get_gcs_policy()
        dataset_policy = resource.get_dataset_policy()
        billing_info = resource.get_billing_info()
        enabled_apis = resource.get_enabled_apis()
        service_config = resource.get_kubernetes_service_config()
        other = json.dumps({'timestamp': resource.get_timestamp()})

        rows = [Inventory(
            inventory_index_id=index.id,
            category=InventoryTypeClass.RESOURCE,
            resource_id=resource.key(),
            resource_type=resource.type(),
            resource_data=json.dumps(resource.data(), sort_keys=True),
            parent_resource_id=None if not parent else parent.key(),
            parent_resource_type=None if not parent else parent.type(),
            other=other,
            inventory_errors=resource.get_warning())]

        if iam_policy:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=InventoryTypeClass.IAM_POLICY,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(iam_policy, sort_keys=True),
                    parent_resource_id=resource.key(),
                    parent_resource_type=resource.type(),
                    other=other,
                    inventory_errors=None))

        if gcs_policy:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=InventoryTypeClass.GCS_POLICY,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(gcs_policy, sort_keys=True),
                    parent_resource_id=resource.key(),
                    parent_resource_type=resource.type(),
                    other=other,
                    inventory_errors=None))

        if dataset_policy:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=InventoryTypeClass.DATASET_POLICY,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(dataset_policy, sort_keys=True),
                    parent_resource_id=resource.key(),
                    parent_resource_type=resource.type(),
                    other=other,
                    inventory_errors=None))

        if billing_info:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=InventoryTypeClass.BILLING_INFO,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(billing_info, sort_keys=True),
                    parent_resource_id=resource.key(),
                    parent_resource_type=resource.type(),
                    other=other,
                    inventory_errors=None))

        if enabled_apis:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=InventoryTypeClass.ENABLED_APIS,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(enabled_apis, sort_keys=True),
                    parent_resource_id=resource.key(),
                    parent_resource_type=resource.type(),
                    other=other,
                    inventory_errors=None))

        if service_config:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=InventoryTypeClass.SERVICE_CONFIG,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(service_config, sort_keys=True),
                    parent_resource_id=resource.key(),
                    parent_resource_type=resource.type(),
                    other=other,
                    inventory_errors=None))

        return rows

    def copy_inplace(self, new_row):
        """Update a database row object from a resource.

        Args:
            new_row (Inventory): the Inventory row of the new resource

        """

        self.category = new_row.category
        self.resource_id = new_row.resource_id
        self.resource_type = new_row.resource_type
        self.resource_data = new_row.resource_data
        self.parent_resource_id = new_row.parent_resource_id
        self.parent_resource_type = new_row.parent_resource_type
        self.other = new_row.other
        self.inventory_errors = new_row.inventory_errors

    def __repr__(self):
        """String representation of the database row object.

        Returns:
            str: A description of inventory_index
        """
        return ('<{}(inventory_index_id=\'{}\', resource_id=\'{}\','
                ' resource_type=\'{}\')>').format(
                    self.__class__.__name__,
                    self.inventory_index_id,
                    self.resource_id,
                    self.resource_type)

    def get_resource_id(self):
        """Get the row's resource id.

        Returns:
            str: resource id.
        """
        return self.resource_id

    def get_resource_type(self):
        """Get the row's resource type.

        Returns:
            str: resource type.
        """
        return self.resource_type

    def get_category(self):
        """Get the row's resource type class.

        Returns:
            str: resource type class.
        """
        return self.category

    def get_parent_resource_id(self):
        """Get the row's parent key.

        Returns:
            str: parent key.
        """
        return self.parent_resource_id

    def get_parent_resource_type(self):
        """Get the row's parent type.

        Returns:
            str: parent type.
        """
        return self.parent_resource_type

    def get_resource_data(self):
        """Get the row's metadata.

        Returns:
            dict: row's metadata.
        """
        return json.loads(self.resource_data)

    def get_resource_data_raw(self):
        """Get the row's data json string.

        Returns:
            str: row's raw data.
        """
        return self.resource_data

    def get_other(self):
        """Get the row's other data.

        Returns:
            dict: row's other data.
        """
        return json.loads(self.other)

    def get_inventory_errors(self):
        """Get the row's error data.

        Returns:
            str: row's error data.
        """
        return self.inventory_errors


class BufferedDbWriter(object):
    """Buffered db writing."""

    def __init__(self, session, max_size=1024):
        """Initialize

        Args:
            session (object): db session
            max_size (int): max size of buffer
        """
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
    def delete(cls, session, inventory_index_id):
        """Delete an inventory index entry by id.

        Args:
            session (object): Database session.
            inventory_index_id (str): Id specifying which inventory to delete.

        Returns:
            InventoryIndex: An expunged entry corresponding the
            inventory_index_id.

        Raises:
            Exception: Reraises any exception.
        """

        try:
            result = cls.get(session, inventory_index_id)
            session.query(Inventory).filter(
                Inventory.inventory_index_id == inventory_index_id).delete()
            session.query(InventoryIndex).filter(
                InventoryIndex.id == inventory_index_id).delete()
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
    def get(cls, session, inventory_index_id):
        """Get an inventory index entry by id.

        Args:
            session (object): Database session
            inventory_index_id (str): Inventory id

        Returns:
            InventoryIndex: Entry corresponding the id
        """

        result = (
            session.query(InventoryIndex).filter(
                InventoryIndex.id == inventory_index_id).one()
        )
        session.expunge(result)
        return result

    @classmethod
    def get_latest_inventory_index_id(cls, session):
        """List all inventory index entries.

        Args:
            session (object): Database session

        Returns:
            str: inventory index id
        """

        inventory_index = (
            session.query(InventoryIndex).filter(
                or_(InventoryIndex.inventory_status == 'SUCCESS',
                    InventoryIndex.inventory_status == 'PARTIAL_SUCCESS')
            ).order_by(InventoryIndex.id.desc()).first())
        session.expunge(inventory_index)
        LOGGER.info(
            'Latest success/partial_success inventory index id is: %s',
            inventory_index.id)
        return inventory_index.id


def initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """

    BASE.metadata.create_all(engine)


class Storage(BaseStorage):
    """Inventory storage used during creation."""

    def __init__(self, session, existing_id=None, readonly=False):
        """Initialize

        Args:
            session (object): db session
            existing_id (str): The inventory id if wants to open an existing one
            readonly (bool): whether to keep the inventory read-only
        """
        self.session = session
        self.opened = False
        self.inventory_index = None
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

    def _open(self, inventory_index_id):
        """Open an existing inventory.

        Args:
            inventory_index_id (str): the id of the inventory to open.

        Returns:
            object: The inventory index db row.
        """

        return (
            self.session.query(InventoryIndex).filter(
                InventoryIndex.id == inventory_index_id).filter(
                    InventoryIndex.inventory_status.in_(
                        [IndexState.SUCCESS, IndexState.PARTIAL_SUCCESS]))
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
            .filter(Inventory.inventory_index_id == self.inventory_index.id)
            .filter(Inventory.resource_id == key))
        rows = qry.all()

        if not rows:
            raise Exception('Resource {} not found in the table'.format(key))
        else:
            return rows

    def open(self, handle=None):
        """Open the storage, potentially create a new index.

        Args:
            handle (str): If None, create a new index instead
                of opening an existing one.

        Returns:
            str: Index id of the opened or created inventory.

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
            self.inventory_index = self._open(existing_id)
        else:
            self.inventory_index = self._create()

        self.opened = True
        self.session.commit()
        if not self.readonly:
            self.session.begin_nested()
        return self.inventory_index.id

    def rollback(self):
        """Roll back the stored inventory, but keep the index entry."""

        try:
            self.buffer.flush()
            self.session.rollback()
            self.inventory_index.complete(status=IndexState.FAILURE)
            self.session.commit()
        finally:
            self.session_completed = True

    def commit(self):
        """Commit the stored inventory."""

        try:
            self.buffer.flush()
            self.session.commit()
            self.inventory_index.complete()
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

        rows = Inventory.from_resource(self.inventory_index, resource)
        for row in rows:
            self.buffer.add(row)

        self.inventory_index.counter += len(rows)

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
            new_rows = Inventory.from_resource(self.inventory_index, resource)
            old_rows = self._get_resource_rows(resource.key())

            new_dict = {row.category: row for row in new_rows}
            old_dict = {row.category: row for row in old_rows}

            for category in InventoryTypeClass.SUPPORTED_TYPECLASS:
                if category in new_dict:
                    if category in old_dict:
                        old_dict[category].copy_inplace(
                            new_dict[category])
                    else:
                        self.session.add(new_dict[category])
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
        self.inventory_index.set_error(self.session, message)

    def warning(self, message):
        """Store a Warning message in storage. This will help debug problems.

        Args:
            message (str): Warning message describing the problem.

        Raises:
            Exception: If the storage was opened readonly.
        """

        if self.readonly:
            raise Exception('Opened storage readonly')
        self.inventory_index.add_warning(self.session, message)

    # pylint: disable=too-many-locals
    def iter(self,
             type_list=None,
             fetch_iam_policy=False,
             fetch_gcs_policy=False,
             fetch_dataset_policy=False,
             fetch_billing_info=False,
             fetch_enabled_apis=False,
             fetch_service_config=False,
             with_parent=False):
        """Iterate the objects in the storage.

        Args:
            type_list (list): List of types to iterate over, or [] for all.
            fetch_iam_policy (bool): Yield iam policies.
            fetch_gcs_policy (bool): Yield gcs policies.
            fetch_dataset_policy (bool): Yield dataset policies.
            fetch_billing_info (bool): Yield project billing info.
            fetch_enabled_apis (bool): Yield project enabled APIs info.
            fetch_service_config (bool): Yield container service config info.
            with_parent (bool): Join parent with results, yield tuples.

        Yields:
            object: Single row object or child/parent if 'with_parent' is set.
        """

        filters = [Inventory.inventory_index_id == self.inventory_index.id]

        if fetch_iam_policy:
            filters.append(
                Inventory.category == InventoryTypeClass.IAM_POLICY)

        elif fetch_gcs_policy:
            filters.append(
                Inventory.category == InventoryTypeClass.GCS_POLICY)

        elif fetch_dataset_policy:
            filters.append(
                Inventory.category ==
                InventoryTypeClass.DATASET_POLICY)

        elif fetch_billing_info:
            filters.append(
                Inventory.category ==
                InventoryTypeClass.BILLING_INFO)

        elif fetch_enabled_apis:
            filters.append(
                Inventory.category ==
                InventoryTypeClass.ENABLED_APIS)

        elif fetch_service_config:
            filters.append(
                Inventory.category ==
                InventoryTypeClass.SERVICE_CONFIG)

        else:
            filters.append(
                Inventory.category == InventoryTypeClass.RESOURCE)

        if type_list:
            filters.append(Inventory.resource_type.in_(type_list))

        if with_parent:
            parent_inventory = aliased(Inventory)
            p_key = parent_inventory.resource_id
            p_type = parent_inventory.resource_type
            base_query = (
                self.session.query(Inventory, parent_inventory)
                .filter(and_(
                    Inventory.parent_resource_id == p_key,
                    Inventory.parent_resource_type == p_type,
                    parent_inventory.inventory_index_id ==
                    self.inventory_index.id)))
        else:
            base_query = self.session.query(Inventory)

        for qry_filter in filters:
            base_query = base_query.filter(qry_filter)

        base_query = base_query.order_by(Inventory.id.asc())

        for row in base_query.yield_per(PER_YIELD):
            yield row

    # pylint: enable=too-many-locals

    def get_root(self):
        """get the resource root from the inventory

        Returns:
            object: A row in gcp_inventory of the root
        """
        return self.session.query(Inventory).filter(
            and_(
                Inventory.inventory_index_id == self.inventory_index.id,
                Inventory.resource_id == Inventory.parent_resource_id,
                Inventory.resource_type == Inventory.parent_resource_type,
                Inventory.category == InventoryTypeClass.RESOURCE
            )).first()

    def type_exists(self,
                    type_list=None):
        """Check if certain types of resources exists in the inventory

        Args:
            type_list (list): List of types to check

        Returns:
            bool: If these types of resources exists
        """
        return self.session.query(exists().where(and_(
            Inventory.inventory_index_id == self.inventory_index.id,
            Inventory.category == InventoryTypeClass.RESOURCE,
            Inventory.resource_type.in_(type_list)
        ))).scalar()

    def __enter__(self):
        """To support with statement for auto closing.

        Returns:
            Storage: The inventory storage object
        """

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
