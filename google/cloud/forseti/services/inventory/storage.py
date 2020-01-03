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
"""Inventory storage implementation."""

from builtins import object
import json
import enum
import threading

from sqlalchemy import and_
from sqlalchemy import BigInteger
from sqlalchemy import case
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import exists
from sqlalchemy import ForeignKey
from sqlalchemy import func
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import or_
from sqlalchemy import select
from sqlalchemy import String
from sqlalchemy import Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import aliased
from sqlalchemy.orm import column_property
from sqlalchemy.orm import joinedload
from sqlalchemy.orm import relationship

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.index_state import IndexState
# pylint: disable=line-too-long
from google.cloud.forseti.services import utils
from google.cloud.forseti.services.inventory.base.storage import Storage as BaseStorage
from google.cloud.forseti.services.scanner.dao import ScannerIndex
# pylint: enable=line-too-long

LOGGER = logger.get_logger(__name__)
BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024


class Categories(enum.Enum):
    """Inventory Categories."""
    resource = 1
    iam_policy = 2
    gcs_policy = 3
    dataset_policy = 4
    billing_info = 5
    enabled_apis = 6
    kubernetes_service_config = 7
    org_policy = 8
    access_policy = 9


SUPPORTED_CATEGORIES = frozenset(item.name for item in list(Categories))


# InventoryWarnings defined first so it can be referenced by InventoryIndex.
class InventoryWarnings(BASE):
    """Warning messages generated during the creation of the inventory."""

    __tablename__ = 'inventory_warnings'

    id = Column(Integer, primary_key=True, autoincrement=True)
    inventory_index_id = Column(BigInteger, ForeignKey('inventory_index.id'))
    resource_full_name = Column(String(2048))
    warning_message = Column(Text)


class InventoryIndex(BASE):
    """Represents a GCP inventory."""

    __tablename__ = 'inventory_index'

    id = Column(BigInteger, primary_key=True)
    created_at_datetime = Column(DateTime)
    completed_at_datetime = Column(DateTime)
    inventory_status = Column(Text)
    schema_version = Column(Integer)
    progress = Column(Text)
    counter = Column(Integer)
    # The inventory_index_warnings column is no longer used by new inventory
    # snapshots, but existing inventories may still have data in this field so
    # it won't be deleted.
    inventory_index_warnings = Column(Text(16777215))
    inventory_index_errors = Column(Text(16777215))
    message = Column(Text(16777215))

    # The warning_count virtual column should be used to test if there are
    # warnings associated with the inventory before the more expensive
    # warning_messages relationship is loaded.
    warning_count = column_property(
        select([func.count(InventoryWarnings.id)]).where(
            InventoryWarnings.inventory_index_id == id).correlate_except(
                InventoryWarnings))

    # Enable cascade='expunge' to ensure the warnings are readable even after
    # a row is expunged from the session.
    warning_messages = relationship('InventoryWarnings', cascade='expunge')

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
            InventoryIndex: InventoryIndex row object.
        """
        utc_now = date_time.get_utc_now_datetime()
        micro_timestamp = date_time.get_utc_now_microtimestamp(utc_now)
        return InventoryIndex(
            id=micro_timestamp,
            created_at_datetime=utc_now,
            completed_at_datetime=None,
            inventory_status=IndexState.CREATED,
            schema_version=CURRENT_SCHEMA,
            counter=0)

    def complete(self, status=IndexState.SUCCESS):
        """Mark the inventory as completed with a final inventory_status.

        Args:
            status (str): Final inventory_status.
        """
        self.completed_at_datetime = date_time.get_utc_now_datetime()
        self.inventory_status = status

    def add_warning(self, engine, resource_full_name, warning):
        """Add a warning to the inventory_warnings table.

        Args:
            engine (sqlalchemy.engine.Engine): Engine to write to.
            resource_full_name (str): The full name of the resource that raised
                the error.
            warning (str): Warning message
        """
        inventory_warning = {'inventory_index_id': self.id,
                             'resource_full_name': resource_full_name,
                             'warning_message': warning}
        engine.execute(InventoryWarnings.__table__.insert(), inventory_warning)

    def set_error(self, message):
        """Indicate a broken import.

        Args:
            message (str): Error message to set.
        """
        self.inventory_index_errors = message

    def get_lifecycle_state_details(self, session, resource_type_input):
        """Count of lifecycle states of the specified resources.

        Generate/return the count of lifecycle states (ACTIVE, DELETE_PENDING)
        of the specific resource type input (project, folder) for this inventory
        index.

        Args:
            session (object) : session object to work on.
            resource_type_input (str) : resource type to get lifecycle states.

        Returns:
            dict: a (lifecycle state -> count) dictionary
        """
        resource_data = Inventory.resource_data

        details = dict(
            session.query(func.json_extract(resource_data, '$.lifecycleState'),
                          func.count())
            .filter(Inventory.inventory_index_id == self.id)
            .filter(Inventory.category == 'resource')
            .filter(Inventory.resource_type == resource_type_input)
            .group_by(func.json_extract(resource_data, '$.lifecycleState'))
            .all())

        LOGGER.debug('Lifecycle details for %s:\n%s',
                     resource_type_input, details)

        # Lifecycle can be None if Forseti is installed to a non-org level.
        for key in list(details.keys()):
            if key is None:
                continue
            new_key = key.replace('\"', '').replace('_', ' ')
            new_key = ' - '.join([resource_type_input, new_key])
            details[new_key] = details.pop(key)

        if len(details) == 1 and list(details.keys())[0] is None:
            return {}

        if len(details) == 1:
            # If the lifecycle state is DELETE PENDING or
            # LIFECYCLE STATE UNSPECIFIED the added_key_string
            # will be RESOURCE_TYPE - ACTIVE, which is then set
            # to 0.
            added_key_str = 'ACTIVE'
            if 'ACTIVE' in list(details.keys())[0]:
                added_key_str = 'DELETE PENDING'
            added_key = ' - '.join([resource_type_input, added_key_str])
            details[added_key] = 0

        return details

    def get_hidden_resource_details(self, session, resource_type):
        """Count of the hidden and shown specified resources.

        Generate/return the count of hidden resources (e.g. dataset) for this
        inventory index.

        Args:
            session (object) : session object to work on.
            resource_type (str) : resource type to find details for.

        Returns:
            dict: a (hidden_resource -> count) dictionary
        """
        details = {}
        resource_id = Inventory.resource_id
        field_label_hidden = resource_type + ' - HIDDEN'
        field_label_shown = resource_type + ' - SHOWN'

        hidden_label = (
            func.count(case([(resource_id.contains('%:~_%', escape='~'), 1)])))

        shown_label = (
            func.count(case([(~resource_id.contains('%:~_%', escape='~'), 1)])))

        details_query = (
            session.query(hidden_label, shown_label)
            .filter(Inventory.inventory_index_id == self.id)
            .filter(Inventory.category == 'resource')
            .filter(Inventory.resource_type == resource_type).one())

        details[field_label_hidden] = details_query[0]
        details[field_label_shown] = details_query[1]

        return details

    def get_summary(self, session):
        """Generate/return an inventory summary for this inventory index.

        Args:
            session (object): session object to work on.

        Returns:
            dict: a (resource type -> count) dictionary
        """

        resource_type = Inventory.resource_type

        summary = dict(
            session.query(resource_type, func.count(resource_type))
            .filter(Inventory.inventory_index_id == self.id)
            .filter(Inventory.category == 'resource')
            .group_by(resource_type).all())

        return summary

    def get_details(self, session):
        """Generate/return inventory details for this inventory index.

        Includes delete pending/active resource types and hidden/shown datasets.

        Args:
            session (object): session object to work on.

        Returns:
            dict: a (resource type -> count) dictionary
        """
        resource_types_with_lifecycle = ['folder', 'organization', 'project']
        resource_types_hidden = ['dataset']

        resource_types_with_details = {'lifecycle':
                                       resource_types_with_lifecycle,
                                       'hidden':
                                       resource_types_hidden}

        details = {}

        for key, value in list(resource_types_with_details.items()):
            if key == 'lifecycle':
                details_function = self.get_lifecycle_state_details
            elif key == 'hidden':
                details_function = self.get_hidden_resource_details
            for resource in value:
                resource_details = details_function(session, resource)
                details.update(resource_details)

        return details


class Inventory(BASE):
    """Resource inventory table."""

    __tablename__ = 'gcp_inventory'

    id = Column(Integer, primary_key=True, autoincrement=True)
    inventory_index_id = Column(BigInteger)
    full_name = Column(String(2048), nullable=False)
    cai_resource_name = Column(String(4096))
    cai_resource_type = Column(String(512))
    category = Column(Enum(Categories))
    resource_type = Column(String(255))
    resource_id = Column(Text)
    resource_data = Column(Text(16777215))
    parent_id = Column(Integer)
    other = Column(Text)

    # The inventory_errors column is no longer used by new inventory snapshots,
    # but existing inventories may still have data in this field so it won't be
    # deleted.
    inventory_errors = Column(Text)

    __table_args__ = (
        Index('idx_resource_category',
              'inventory_index_id',
              'resource_type',
              'category'),)

    @staticmethod
    def get_schema_update_actions():
        """Maintain all the schema changes for this table.

        Returns:
            dict: A mapping of Action: Column.
        """
        columns_to_create = [Column('cai_resource_type',
                                    String(512),
                                    default=''),
                             Column('cai_resource_name',
                                    String(4096),
                                    default=''),
                             Column('full_name',
                                    String(2048),
                                    nullable=False)]

        schema_update_actions = {'CREATE': columns_to_create}
        return schema_update_actions

    # pylint: disable=too-many-locals
    @classmethod
    def from_resource(cls, index, resource):
        """Creates a database row object from a crawled resource.

        Args:
            index (InventoryIndex): InventoryIndex to associate.
            resource (Resource): Crawled resource.

        Returns:
            Tuple[dict, list]: A tuple containing a single row for the main
                resource, and a list of rows for any additional policies
                attached to the resource.
        """

        parent = resource.parent()
        iam_policy = resource.get_iam_policy()
        org_policies = resource.get_org_policy()
        access_policy = resource.get_access_policy()
        gcs_policy = resource.get_gcs_policy()
        dataset_policy = resource.get_dataset_policy()
        billing_info = resource.get_billing_info()
        enabled_apis = resource.get_enabled_apis()
        service_config = resource.get_kubernetes_service_config()

        cai_resource_name = ''
        cai_resource_type = ''

        if resource.metadata():
            cai_resource_name = resource.metadata().cai_name
            cai_resource_type = resource.metadata().cai_type

        base_row = {
            'cai_resource_name': cai_resource_name,
            'cai_resource_type': cai_resource_type,
            'inventory_index_id': index.id,
            'resource_id': resource.key(),
            'resource_type': resource.type(),
            'other': json.dumps({'timestamp': resource.get_timestamp()}),
        }

        resource_row = dict(
            base_row,
            category=Categories.resource,
            resource_data=json.dumps(resource.data(), sort_keys=True),
            full_name=resource.get_full_resource_name(),
            parent_id=None if not parent else parent.inventory_key(),
            inventory_errors=resource.get_warning())

        policy_rows = []
        if iam_policy:
            policy_rows.append(dict(
                base_row,
                category=Categories.iam_policy,
                full_name=cls._get_policy_full_name(resource, 'iam_policy'),
                resource_data=json.dumps(iam_policy, sort_keys=True)))

        if org_policies:
            for org_policy, _ in org_policies:
                policy_rows.append(dict(
                    base_row,
                    category=Categories.org_policy,
                    full_name=cls._get_policy_full_name(resource, 'org_policy'),
                    resource_data=json.dumps(org_policy, sort_keys=True)))

        if access_policy:
            policy_rows.append(dict(
                base_row,
                category=Categories.access_policy,
                full_name=cls._get_policy_full_name(resource, 'access_policy'),
                resource_data=json.dumps(access_policy, sort_keys=True)))

        if gcs_policy:
            policy_rows.append(dict(
                base_row,
                category=Categories.gcs_policy,
                full_name=cls._get_policy_full_name(resource, 'gcs_policy'),
                resource_data=json.dumps(gcs_policy, sort_keys=True)))

        if dataset_policy:
            policy_rows.append(dict(
                base_row,
                category=Categories.dataset_policy,
                full_name=cls._get_policy_full_name(resource, 'dataset_policy'),
                resource_data=json.dumps(dataset_policy, sort_keys=True)))

        if billing_info:
            policy_rows.append(dict(
                base_row,
                category=Categories.billing_info,
                full_name=cls._get_policy_full_name(resource, 'billing_info'),
                resource_data=json.dumps(billing_info, sort_keys=True)))

        if enabled_apis:
            policy_rows.append(dict(
                base_row,
                category=Categories.enabled_apis,
                full_name=cls._get_policy_full_name(resource, 'enabled_apis'),
                resource_data=json.dumps(enabled_apis, sort_keys=True)))

        if service_config:
            policy_rows.append(dict(
                base_row,
                category=Categories.kubernetes_service_config,
                full_name=cls._get_policy_full_name(
                    resource, 'kubernetes_service_config'),
                resource_data=json.dumps(service_config, sort_keys=True)))

        return resource_row, policy_rows

    @classmethod
    def _get_policy_full_name(cls, resource, policy_name):
        """Create a full name for a resource policy.

        Args:
            resource (Resource): Crawled resource.
            policy_name (str): The category name for the policy data.

        Returns:
            str: A full name for the policy.
        """
        type_name = utils.to_type_name(policy_name, resource.key())
        return utils.to_full_resource_name(resource.get_full_resource_name(),
                                           type_name)

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

    def get_cai_resource_name(self):
        """Get the row's cai resource name.

        Returns:
            str: cai resource name.
        """
        return self.cai_resource_name

    def get_cai_resource_type(self):
        """Get the row's cai resource type.

        Returns:
            str: cai resource type.
        """
        return self.cai_resource_type

    def get_full_name(self):
        """Get the row's full name.

        Returns:
            str: resource full name.
        """
        return self.full_name

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
        """Get the row's data category.

        Returns:
            str: data category.
        """
        return self.category.name

    def get_parent_id(self):
        """Get the row's parent id.

        Returns:
            int: parent id.
        """
        return self.parent_id

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
                Inventory.inventory_index_id == inventory_index_id
            ).delete()
            session.query(InventoryWarnings).filter(
                InventoryWarnings.inventory_index_id == inventory_index_id
            ).delete()
            session.query(InventoryIndex).filter(
                InventoryIndex.id == inventory_index_id
            ).delete()
            session.commit()
            return result
        except Exception as e:
            LOGGER.exception(e)
            session.rollback()
            raise

    @classmethod
    def list(cls, session):
        """List all inventory index entries.

        Args:
            session (object): Database session.

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
            session (object): Database session.
            inventory_index_id (str): Inventory id.

        Returns:
            InventoryIndex: Entry corresponding the id
        """

        result = session.query(InventoryIndex).options(
            joinedload(InventoryIndex.warning_messages)).filter(
                InventoryIndex.id == inventory_index_id).one()
        session.expunge(result)
        return result

    @classmethod
    def get_latest_inventory_index_id(cls, session):
        """List all inventory index entries.

        Args:
            session (object): Database session.

        Returns:
            int64: inventory index id
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

    @classmethod
    # pylint: disable=invalid-name
    def get_inventory_index_id_by_scanner_index_id(cls,
                                                   session,
                                                   scanner_index_id):
        """List all inventory index entries.

        Args:
            session (object): Database session.
            scanner_index_id (int): id of the scanner in scanner_index table

        Returns:
            int64: inventory index id
        """

        query_result = (
            session.query(ScannerIndex).filter(
                ScannerIndex.id == scanner_index_id
            ).order_by(ScannerIndex.inventory_index_id.desc()).first())
        session.expunge(query_result)
        LOGGER.info(
            'Found inventory_index_id %s from scanner_index_id %s.',
            query_result.inventory_index_id, scanner_index_id)
        return query_result.inventory_index_id

    @classmethod
    def get_inventory_indexes_older_than_cutoff(  # pylint: disable=invalid-name
            cls, session, cutoff_datetime):
        """Get all inventory index entries older than the cutoff.

        Args:
            session (object): Database session.
            cutoff_datetime (datetime): The cutoff point to find any
                older inventory index entries.

        Returns:
            list: InventoryIndex
        """

        inventory_indexes = session.query(InventoryIndex).filter(
            InventoryIndex.created_at_datetime < cutoff_datetime).all()
        session.expunge_all()
        return inventory_indexes

    @classmethod
    def iter(cls,
             session,
             inventory_index_id,
             type_list=None,
             fetch_category=Categories.resource,
             with_parent=False):
        """Iterate the objects in the storage.

        Args:
            session (object): Database session.
            inventory_index_id (str): the id of the inventory to open.
            type_list (list): List of types to iterate over, or [] for all.
            fetch_category (Categories): The category of data to fetch.
            with_parent (bool): Join parent with results, yield tuples.

        Yields:
            object: Single row object or child/parent if 'with_parent' is set.
        """
        filters = [Inventory.inventory_index_id == inventory_index_id,
                   Inventory.category == fetch_category]

        if type_list:
            filters.append(Inventory.resource_type.in_(type_list))

        if with_parent:
            parent_inventory = aliased(Inventory)
            p_id = parent_inventory.id
            base_query = (
                session.query(Inventory, parent_inventory)
                .filter(Inventory.parent_id == p_id))
        else:
            base_query = session.query(Inventory)

        for qry_filter in filters:
            base_query = base_query.filter(qry_filter)

        base_query = base_query.order_by(Inventory.id.asc())

        for row in base_query.yield_per(PER_YIELD):
            yield row

    @classmethod
    def get_root(cls, session, inventory_index_id):
        """Get the resource root from the inventory.

        Args:
            session (object): Database session.
            inventory_index_id (str): the id of the inventory to query.

        Returns:
            object: A row in gcp_inventory of the root
        """
        # Comparison to None needed to compare to Null in SQL.
        # pylint: disable=singleton-comparison
        root = session.query(Inventory).filter(
            and_(
                Inventory.inventory_index_id == inventory_index_id,
                Inventory.parent_id == None,
                Inventory.category == Categories.resource,
                Inventory.resource_type.in_(['composite_root',
                                             'organization',
                                             'folder',
                                             'project'])
            )).first()
        # pylint: enable=singleton-comparison

        LOGGER.debug('Root resource: %s', root)
        return root

    @classmethod
    def type_exists(cls,
                    session,
                    inventory_index_id,
                    type_list=None):
        """Check if certain types of resources exists in the inventory.

        Args:
            session (object): Database session.
            inventory_index_id (str): the id of the inventory to query.
            type_list (list): List of types to check.

        Returns:
            bool: If these types of resources exists.
        """
        return session.query(exists().where(and_(
            Inventory.inventory_index_id == inventory_index_id,
            Inventory.category == Categories.resource,
            Inventory.resource_type.in_(type_list)
        ))).scalar()


def initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """
    BASE.metadata.create_all(engine)


class Storage(BaseStorage):
    """Inventory storage used during creation."""

    def __init__(self, session, engine):
        """Initialize

        Args:
            session (object): db session.
            engine (sqlalchemy.engine.Engine): db engine.
        """
        self.session = session
        self.engine = engine
        self.opened = False
        self.inventory_index = None
        self.session_completed = False
        self._wrote_resources = set()
        self._storage_lock = threading.Lock()

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
            self.session.commit()
            LOGGER.info('Created Inventory Index %s', index.id)
            self.session.expunge(index)
        except Exception as e:
            LOGGER.exception(e)
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

        if self.opened:
            raise Exception('open called before')

        # Should we create a new entry or are we opening an existing one?
        if handle:
            self.inventory_index = self._open(handle)
        else:
            self.inventory_index = self._create()

        self.opened = True
        return self.inventory_index.id

    def rollback(self):
        """Roll back the stored inventory, but keep the index entry."""

        try:
            # Delete any rows that had been added to the inventory for this
            # instance of the inventory.
            self.engine.execute(Inventory.__table__.delete().where(
                Inventory.inventory_index_id == self.inventory_index.id))
            self.commit()
        finally:
            self.session_completed = True

    def commit(self):
        """Commit the stored inventory."""
        if self.inventory_index.inventory_index_warnings:
            status = IndexState.PARTIAL_SUCCESS
        elif self.inventory_index.inventory_index_errors:
            status = IndexState.FAILURE
        else:
            status = IndexState.SUCCESS
        try:
            self.engine.execute(InventoryIndex.__table__.update().where(
                InventoryIndex.id == self.inventory_index.id).values(
                    completed_at_datetime=(
                        date_time.get_utc_now_datetime()),
                    inventory_status=status,
                    counter=self.inventory_index.counter,
                    inventory_index_errors=(
                        self.inventory_index.inventory_index_errors),
                    inventory_index_warnings=(
                        self.inventory_index.inventory_index_warnings),
                    message=self.inventory_index.message))
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

        if not self.session_completed:
            raise Exception('Need to perform commit or rollback before close')

        self.opened = False

    def write(self, resource):
        """Write a resource to the storage and updates its row

        Args:
            resource (object): Resource object to store in db.
        """
        # Use a lock to quickly check if this is a duplicate resource before
        # updating the cache and proceeding.
        with self._storage_lock:
            if resource.get_full_resource_name() in self._wrote_resources:
                LOGGER.warning('Duplicate Resource in inventory, skipping %s',
                               resource.get_full_resource_name())
                return
            self._wrote_resources.add(resource.get_full_resource_name())

        (resource_row, policy_rows) = Inventory.from_resource(
            self.inventory_index, resource)

        # Insert first row to get the primary key for the resource
        result = self.engine.execute(Inventory.__table__.insert(), resource_row)
        resource_id = result.inserted_primary_key[0]
        resource.set_inventory_key(resource_id)

        # Insert any remaining rows in bulk.
        if policy_rows:
            # Set the parent id for policies to the main resource
            for row in policy_rows:
                row['parent_id'] = resource_id
            self.engine.execute(Inventory.__table__.insert(), policy_rows)

        with self._storage_lock:
            self.inventory_index.counter += 1 + len(policy_rows)

    def error(self, message):
        """Store a fatal error in storage. This will help debug problems.

        Args:
            message (str): Error message describing the problem.
        """
        with self._storage_lock:
            self.inventory_index.set_error(message)
            self.session.commit()

    def warning(self, resource_full_name, message):
        """Store a Warning message in storage. This will help debug problems.

        Args:
            resource_full_name (str): The full name of the resource that raised
                the error.
            message (str): Warning message describing the problem.
        """
        self.inventory_index.add_warning(self.engine,
                                         resource_full_name,
                                         message)

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
