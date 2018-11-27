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
# pylint: disable=too-many-lines

import json
import enum

from sqlalchemy import and_
from sqlalchemy import BigInteger
from sqlalchemy import case
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import exists
from sqlalchemy import func
from sqlalchemy import Index
from sqlalchemy import Integer
from sqlalchemy import LargeBinary
from sqlalchemy import or_
from sqlalchemy import PrimaryKeyConstraint
from sqlalchemy import String
from sqlalchemy import Table
from sqlalchemy import Text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import aliased
from sqlalchemy.orm import mapper

from google.cloud.asset_v1beta1.proto import assets_pb2
from google.protobuf import json_format

from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util.index_state import IndexState
# pylint: disable=line-too-long
from google.cloud.forseti.services.inventory.base.storage import Storage as BaseStorage
from google.cloud.forseti.services.scanner.dao import ScannerIndex
# pylint: enable=line-too-long

LOGGER = logger.get_logger(__name__)
BASE = declarative_base()
CURRENT_SCHEMA = 1
PER_YIELD = 1024
MAX_ALLOWED_PACKET = 32 * 1024 * 1024  # 32 Mb default mysql max packet size


class Categories(enum.Enum):
    """Inventory Categories."""
    resource = 1
    iam_policy = 2
    gcs_policy = 3
    dataset_policy = 4
    billing_info = 5
    enabled_apis = 6
    kubernetes_service_config = 7


class ContentTypes(enum.Enum):
    """Cloud Asset Inventory Content Types."""
    resource = 1
    iam_policy = 2


SUPPORTED_CATEGORIES = frozenset(item.name for item in list(Categories))
SUPPORTED_CONTENT_TYPES = frozenset(item.name for item in list(ContentTypes))


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
    inventory_index_warnings = Column(Text(16777215))
    inventory_index_errors = Column(Text(16777215))
    message = Column(Text(16777215))

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

        for key in details.keys():
            new_key = key.replace('\"', '').replace('_', ' ')
            new_key = ' - '.join([resource_type_input, new_key])
            details[new_key] = details.pop(key)

        if len(details) == 1:
            if 'ACTIVE' in details.keys()[0]:
                added_key_str = 'DELETE PENDING'
            elif 'DELETE PENDING' in details.keys()[0]:
                added_key_str = 'ACTIVE'
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

        for key, value in resource_types_with_details.items():
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
    category = Column(Enum(Categories))
    resource_type = Column(String(255))
    resource_id = Column(Text)
    resource_data = Column(Text(16777215))
    parent_id = Column(Integer)
    other = Column(Text)
    inventory_errors = Column(Text)

    __table_args__ = (
        Index('idx_resource_category',
              'inventory_index_id',
              'resource_type',
              'category'),
        Index('idx_parent_id',
              'parent_id'))

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
            category=Categories.resource,
            resource_id=resource.key(),
            resource_type=resource.type(),
            resource_data=json.dumps(resource.data(), sort_keys=True),
            parent_id=None if not parent else parent.inventory_key(),
            other=other,
            inventory_errors=resource.get_warning())]

        if iam_policy:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=Categories.iam_policy,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(iam_policy, sort_keys=True),
                    other=other,
                    inventory_errors=None))

        if gcs_policy:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=Categories.gcs_policy,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(gcs_policy, sort_keys=True),
                    other=other,
                    inventory_errors=None))

        if dataset_policy:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=Categories.dataset_policy,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(dataset_policy, sort_keys=True),
                    other=other,
                    inventory_errors=None))

        if billing_info:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=Categories.billing_info,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(billing_info, sort_keys=True),
                    other=other,
                    inventory_errors=None))

        if enabled_apis:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=Categories.enabled_apis,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(enabled_apis, sort_keys=True),
                    other=other,
                    inventory_errors=None))

        if service_config:
            rows.append(
                Inventory(
                    inventory_index_id=index.id,
                    category=Categories.kubernetes_service_config,
                    resource_id=resource.key(),
                    resource_type=resource.type(),
                    resource_data=json.dumps(service_config, sort_keys=True),
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


class CaiTemporaryStore(object):
    """CAI temporary inventory table."""

    __tablename__ = 'cai_temporary_store'

    # Class members created in initialize() by mapper()
    name = None
    parent_name = None
    content_type = None
    asset_type = None
    asset_data = None

    def __init__(self, name, parent_name, content_type, asset_type, asset_data):
        """Initialize database column.

        Manually defined so that the collation value can be overriden at run
        time for this database table.

        Args:
            name (str): The asset name.
            parent_name (str): The asset name of the parent resource.
            content_type (ContentTypes): The asset data content type.
            asset_type (str): The asset data type.
            asset_data (str): The asset data as a serialized binary blob.
        """
        self.name = name
        self.parent_name = parent_name
        self.content_type = content_type
        self.asset_type = asset_type
        self.asset_data = asset_data

    @classmethod
    def initialize(cls, metadata, collation='utf8_bin'):
        """Create the table schema based on run time arguments.

        Used to fix the column collation value for non-MySQL database engines.

        Args:
            metadata (object): The sqlalchemy MetaData to associate the table
                with.
            collation (str): The collation value to use.
        """
        if 'cai_temporary_store' not in metadata.tables:
            my_table = Table('cai_temporary_store', metadata,
                             Column('name', String(512, collation=collation),
                                    nullable=False),
                             Column('parent_name', String(255), nullable=True),
                             Column('content_type', Enum(ContentTypes),
                                    nullable=False),
                             Column('asset_type', String(255), nullable=False),
                             Column('asset_data',
                                    LargeBinary(length=(2**32) - 1),
                                    nullable=False),
                             Index('idx_parent_name', 'parent_name'),
                             PrimaryKeyConstraint('content_type',
                                                  'asset_type',
                                                  'name',
                                                  name='cai_temp_store_pk'))

            mapper(cls, my_table)

    def extract_asset_data(self, content_type):
        """Extracts the data from the asset protobuf based on the content type.

        Args:
            content_type (ContentTypes): The content type data to extract.

        Returns:
            dict: The dict representation of the asset data.
        """
        # The no-member is a false positive for the dynamic protobuf class.
        # pylint: disable=no-member
        asset_pb = assets_pb2.Asset.FromString(self.asset_data)
        # pylint: enable=no-member
        if content_type == ContentTypes.resource:
            return json_format.MessageToDict(asset_pb.resource.data)
        elif content_type == ContentTypes.iam_policy:
            return json_format.MessageToDict(asset_pb.iam_policy)

        return json_format.MessageToDict(asset_pb)

    @classmethod
    def from_json(cls, asset_json):
        """Creates a database row object from the json data in a dump file.

        Args:
            asset_json (str): The json representation of an Asset.

        Returns:
            object: database row object or None if there is no data.
        """
        asset_pb = json_format.Parse(asset_json, assets_pb2.Asset())
        if len(asset_pb.name) > 512:
            LOGGER.warn('Skipping insert of asset %s, name too long.',
                        asset_pb.name)
            return None

        if asset_pb.HasField('resource'):
            content_type = ContentTypes.resource
            parent_name = cls._get_parent_name(asset_pb)
        elif asset_pb.HasField('iam_policy'):
            content_type = ContentTypes.iam_policy
            parent_name = asset_pb.name
        else:
            return None

        return cls(
            name=asset_pb.name,
            parent_name=parent_name,
            content_type=content_type,
            asset_type=asset_pb.asset_type,
            asset_data=asset_pb.SerializeToString()
        )

    @classmethod
    def delete_all(cls, session):
        """Deletes all rows from this table.

        Args:
            session (object): db session

        Returns:
            int: The number of rows deleted.

        Raises:
            Exception: Reraises any exception.
        """
        try:
            num_rows = session.query(cls).delete()
            session.commit()
            return num_rows
        except Exception as e:
            LOGGER.exception(e)
            session.rollback()
            raise

    @staticmethod
    def _get_parent_name(asset_pb):
        """Determines the parent name from the resource data.

        Args:
            asset_pb (assets_pb2.Asset): An Asset protobuf object.

        Returns:
            str: The parent name for the resource.
        """
        if asset_pb.resource.parent:
            return asset_pb.resource.parent

        if (asset_pb.asset_type.startswith('google.appengine') or
                asset_pb.asset_type.startswith('google.bigquery') or
                asset_pb.asset_type.startswith('google.spanner')):
            # Strip off the last two segments of the name to get the parent
            return '/'.join(asset_pb.name.split('/')[:-2])

        LOGGER.debug('Could not determine parent name for %s', asset_pb)
        return ''


class BufferedDbWriter(object):
    """Buffered db writing."""

    def __init__(self,
                 session,
                 max_size=1024,
                 max_packet_size=MAX_ALLOWED_PACKET * .75,
                 commit_on_flush=False):
        """Initialize

        Args:
            session (object): db session
            max_size (int): max size of buffer
            max_packet_size (int): max size of a packet to send to SQL
            commit_on_flush (bool): If true, the session is committed to the
                database when the data is flushed.
        """
        self.session = session
        self.buffer = []
        self.estimated_packet_size = 0
        self.max_size = max_size
        self.max_packet_size = max_packet_size
        self.commit_on_flush = commit_on_flush

    def add(self, obj, estimated_length=0):
        """Add an object to the buffer to write to db.

        Args:
            obj (object): Object to write to db.
            estimated_length (int): The estimated length of this object.
        """

        self.buffer.append(obj)
        self.estimated_packet_size += estimated_length
        if (self.estimated_packet_size > self.max_packet_size or
                len(self.buffer) >= self.max_size):
            self.flush()

    def flush(self):
        """Flush all pending objects to the database."""

        self.session.bulk_save_objects(self.buffer)
        self.session.flush()
        if self.commit_on_flush:
            self.session.commit()
        self.estimated_packet_size = 0
        self.buffer = []


class CaiDataAccess(object):
    """Access to the CAI temporary store table."""

    @staticmethod
    def clear_cai_data(session):
        """Deletes all temporary CAI data from the cai temporary table.

        Args:
            session (object): Database session.

        Returns:
            int: The number of rows deleted.
        """
        num_rows = 0
        try:
            num_rows = CaiTemporaryStore.delete_all(session)
        except SQLAlchemyError as e:
            LOGGER.exception('Attempt to delete data from CAI temporary store '
                             'failed, disabling the use of CAI: %s', e)

        return num_rows

    @staticmethod
    def populate_cai_data(data, session):
        """Add assets from cai data dump into cai temporary table.

        Args:
            data (file): A file like object, line delimeted text dump of json
                data representing assets from Cloud Asset Inventory exportAssets
                API.
            session (object): Database session.

        Returns:
            int: The number of rows inserted
        """
        # CAI data can be large, so limit the number of rows written at one
        # time to 512.
        commit_buffer = BufferedDbWriter(session,
                                         max_size=512,
                                         commit_on_flush=True)
        num_rows = 0
        try:
            for line in data:
                if not line:
                    continue

                try:
                    row = CaiTemporaryStore.from_json(line.strip())
                except json_format.ParseError as e:
                    # If the public protobuf definition differs from the
                    # internal representation of the resource content in CAI
                    # then the json_format module will throw a ParseError. The
                    # crawler automatically falls back to using the live API
                    # when this happens, so no content is lost.
                    resource = json.loads(line)
                    if 'iam_policy' in resource:
                        content_type = 'iam_policy'
                    elif 'resource' in resource:
                        content_type = 'resource'
                    else:
                        content_type = 'none'
                    LOGGER.info('Protobuf parsing error %s, falling back to '
                                'live API for resource %s, asset type %s, '
                                'content type %s', e, resource.get('name', ''),
                                resource.get('asset_type', ''), content_type)
                    continue
                if row:
                    # Overestimate the packet length to ensure max size is never
                    # exceeded. The actual length is closer to len(line) * 1.5.
                    commit_buffer.add(row, estimated_length=len(line) * 2)
                    num_rows += 1
            commit_buffer.flush()
        except SQLAlchemyError as e:
            LOGGER.exception('Error populating CAI data: %s', e)
            session.rollback()
        return num_rows

    @staticmethod
    def iter_cai_assets(content_type, asset_type, parent_name, session):
        """Iterate the objects in the cai temporary table.

        Args:
            content_type (ContentTypes): The content type to return.
            asset_type (str): The asset type to return.
            parent_name (str): The parent resource to iter children under.
            session (object): Database session.

        Yields:
            object: The content_type data for each resource.
        """
        filters = [
            CaiTemporaryStore.content_type == content_type,
            CaiTemporaryStore.asset_type == asset_type,
            CaiTemporaryStore.parent_name == parent_name,
        ]
        base_query = session.query(CaiTemporaryStore)

        for qry_filter in filters:
            base_query = base_query.filter(qry_filter)

        base_query = base_query.order_by(CaiTemporaryStore.name.asc())

        for row in base_query.yield_per(PER_YIELD):
            yield row.extract_asset_data(content_type)

    @staticmethod
    def fetch_cai_asset(content_type, asset_type, name, session):
        """Returns a single resource from the cai temporary store.

        Args:
            content_type (ContentTypes): The content type to return.
            asset_type (str): The asset type to return.
            name (str): The resource to return.
            session (object): Database session.

        Returns:
            dict: The content data for the specified resource.
        """
        filters = [
            CaiTemporaryStore.content_type == content_type,
            CaiTemporaryStore.asset_type == asset_type,
            CaiTemporaryStore.name == name,
        ]
        base_query = session.query(CaiTemporaryStore)

        for qry_filter in filters:
            base_query = base_query.filter(qry_filter)

        row = base_query.one_or_none()

        if row:
            return row.extract_asset_data(content_type)

        return {}


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
        except Exception as e:
            LOGGER.exception(e)
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
    def get_inventory_index_id_by_scanner(cls, session, scanner_index_id):
        """List all inventory index entries.

        Args:
            session (object): Database session
            scanner_index_id (int): id of the scanner in scanner_index table

        Returns:
            int64: inventory index id
        """

        inventory_index = (
            session.query(InventoryIndex)
                .outerjoin(ScannerIndex,
                           ScannerIndex.inventory_index_id == InventoryIndex.id)
                .filter(
                and_(ScannerIndex.id == scanner_index_id,
                     or_(InventoryIndex.inventory_status == 'SUCCESS',
                         InventoryIndex.inventory_status == 'PARTIAL_SUCCESS'))
            ).order_by(InventoryIndex.id.desc()).first())
        session.expunge(inventory_index)
        LOGGER.info(
            'Latest success/partial_success inventory index id is: %s',
            inventory_index.id)
        return inventory_index.id

    @classmethod
    def get_inventory_indexes_older_than_cutoff(  # pylint: disable=invalid-name
            cls, session, cutoff_datetime):
        """Get all inventory index entries older than the cutoff.

        Args:
            session (object): Database session
            cutoff_datetime (datetime): The cutoff point to find any
                older inventory index entries.

        Returns:
            list: InventoryIndex
        """

        inventory_indexes = session.query(InventoryIndex).filter(
            InventoryIndex.created_at_datetime < cutoff_datetime).all()
        session.expunge_all()
        return inventory_indexes


def initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """
    dialect = engine.dialect.name
    if dialect == 'sqlite':
        collation = 'binary'
    else:
        collation = 'utf8_bin'

    CaiTemporaryStore.initialize(BASE.metadata, collation)
    BASE.metadata.create_all(engine)


class Storage(BaseStorage):
    """Inventory storage used during creation."""

    def __init__(self, session, existing_id=0, readonly=False):
        """Initialize

        Args:
            session (object): db session.
            existing_id (int64): The inventory id if wants to open an existing
                inventory.
            readonly (bool): whether to keep the inventory read-only.
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

    def _get_resource_rows(self, key, resource_type):
        """ Get the rows in the database for a certain resource

        Args:
            key (str): The key of the resource
            resource_type (str): The type of the resource

        Returns:
            object: The inventory db rows of the resource,
            IAM policy and GCS policy.

        Raises:
            Exception: if there is no such row or more than one.
        """

        rows = self.session.query(Inventory).filter(
            and_(
                Inventory.inventory_index_id == self.inventory_index.id,
                Inventory.resource_id == key,
                Inventory.resource_type == resource_type
            )).all()

        if not rows:
            raise Exception('Resource {} not found in the table'.format(key))
        else:
            return rows

    def _get_resource_id(self, resource):
        """Checks if a resource exists already in the inventory.

        Args:
            resource (object): Resource object to check against the db.

        Returns:
            int: The resource id of the existing resource, else 0.
        """
        row = self.session.query(Inventory.id).filter(
            and_(
                Inventory.inventory_index_id == self.inventory_index.id,
                Inventory.category == Categories.resource,
                Inventory.resource_type == resource.type(),
                Inventory.resource_id == resource.key(),
            )).one_or_none()

        if row:
            return row.id

        return 0

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
            self.session.commit()  # commit only on create.

        self.opened = True
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

        previous_id = self._get_resource_id(resource)
        if previous_id:
            resource.set_inventory_key(previous_id)
            self.update(resource)
            return

        rows = Inventory.from_resource(self.inventory_index, resource)

        for row in rows:
            if row.category == Categories.resource:
                # Force flush to insert the resource row in order to get the
                # inventory id value. This is used to tie child resources
                # and related data back to the parent resource row and to
                # check for duplicate resources.
                self.session.add(row)
                self.session.flush()
                resource.set_inventory_key(row.id)
            else:
                row.parent_id = resource.inventory_key()
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
            old_rows = self._get_resource_rows(
                resource.key(), resource.type())

            new_dict = {row.category.name: row for row in new_rows}
            old_dict = {row.category.name: row for row in old_rows}

            for category in SUPPORTED_CATEGORIES:
                if category in new_dict:
                    if category in old_dict:
                        old_dict[category].copy_inplace(
                            new_dict[category])
                    else:
                        new_dict[category].parent_id = resource.inventory_key()
                        self.session.add(new_dict[category])
            self.session.commit()
        except Exception as e:
            LOGGER.exception(e)
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
                Inventory.category == Categories.iam_policy)

        elif fetch_gcs_policy:
            filters.append(
                Inventory.category == Categories.gcs_policy)

        elif fetch_dataset_policy:
            filters.append(
                Inventory.category == Categories.dataset_policy)

        elif fetch_billing_info:
            filters.append(
                Inventory.category == Categories.billing_info)

        elif fetch_enabled_apis:
            filters.append(
                Inventory.category == Categories.enabled_apis)

        elif fetch_service_config:
            filters.append(
                Inventory.category == Categories.kubernetes_service_config)

        else:
            filters.append(
                Inventory.category == Categories.resource)

        if type_list:
            filters.append(Inventory.resource_type.in_(type_list))

        if with_parent:
            parent_inventory = aliased(Inventory)
            p_id = parent_inventory.id
            base_query = (
                self.session.query(Inventory, parent_inventory)
                .filter(Inventory.parent_id == p_id))
        else:
            base_query = self.session.query(Inventory)

        for qry_filter in filters:
            base_query = base_query.filter(qry_filter)

        base_query = base_query.order_by(Inventory.id.asc())

        for row in base_query.yield_per(PER_YIELD):
            yield row

    def get_root(self):
        """get the resource root from the inventory

        Returns:
            object: A row in gcp_inventory of the root
        """
        # Comparison to None needed to compare to Null in SQL.
        # pylint: disable=singleton-comparison
        root = self.session.query(Inventory).filter(
            and_(
                Inventory.inventory_index_id == self.inventory_index.id,
                Inventory.parent_id == None,
                Inventory.category == Categories.resource,
                Inventory.resource_type.in_(['organization',
                                             'folder',
                                             'project'])
            )).first()
        # pylint: enable=singleton-comparison

        LOGGER.debug('Root resource: %s', root)
        return root

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
            Inventory.category == Categories.resource,
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
