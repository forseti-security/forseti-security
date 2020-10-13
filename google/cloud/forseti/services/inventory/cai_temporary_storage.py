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
"""Inventory temporary storage for Cloud Asset data."""
import dateutil.parser
import enum
import json
import os
import tempfile

from retrying import retry
from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Enum
from sqlalchemy import Index
from sqlalchemy import PrimaryKeyConstraint
from sqlalchemy import String
from sqlalchemy import LargeBinary
from sqlalchemy import func, and_
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.pool import SingletonThreadPool

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.dao import create_engine
from google.cloud.forseti.services.inventory.base.gcp import AssetMetadata

LOGGER = logger.get_logger(__name__)
BASE = declarative_base()

# Maximum insert size, used to bound the memory used to cache rows to insert
# before they are flushed to the database. Larger values allow for more
# efficient index writing by sqlite at the cost of more process memory.
#
# NOTE: This is different from https://www.sqlite.org/limits.html#max_sql_length
# as that limit applies to the individual SQL insert statements, not the
# combined size of all values inserted at one time.
#
# Set to 32 MB as a balance between frequency of writes and memory. This value
# should be re-evaluated for large Virtual Machines.
MAX_ALLOWED_INSERT_SIZE = 32 * 1024 * 1024  # 32 Megabytes


class ContentTypes(enum.Enum):
    """Cloud Asset Inventory Content Types."""
    resource = 1
    iam_policy = 2
    org_policy = 3
    access_policy = 4
    access_level = 5
    service_perimeter = 6


SUPPORTED_CONTENT_TYPES = frozenset(item.name for item in list(ContentTypes))


class CaiTemporaryStore(BASE):
    """CAI temporary inventory table."""

    __tablename__ = 'cai_temporary_store'

    # Class members created in initialize() by mapper()
    name = Column(String(2048, collation='binary'), nullable=False)
    parent_name = Column(String(255), nullable=True)
    content_type = Column(Enum(ContentTypes), nullable=False)
    asset_type = Column(String(255), nullable=False)
    asset_data = Column(LargeBinary(length=(2**32) - 1), nullable=False)
    update_time = Column(DateTime, nullable=True)

    __table_args__ = (
        Index('idx_parent_name', 'parent_name'),
        Index('idx_name_update_time', 'name', 'update_time'),
        PrimaryKeyConstraint('content_type',
                             'asset_type',
                             'name',
                             'update_time',
                             name='cai_temp_store_pk'))

    # Assets with no parent resource.
    UNPARENTED_ASSETS = frozenset([
        'cloudresourcemanager.googleapis.com/Organization',
        'cloudbilling.googleapis.com/BillingAccount',
    ])

    @classmethod
    def from_json(cls, asset_json):
        """Creates a database row object from the json data in a dump file.

        Args:
            asset_json (str): The json representation of an Asset.

        Returns:
            dict: database row dictionary or None if there is no data.
        """
        asset = json.loads(asset_json)
        if len(asset['name']) > 2048:
            LOGGER.warning('Skipping insert of asset %s, name too long.',
                           asset['name'])
            return None

        name = ''
        if 'resource' in asset:
            content_type = 'resource'
            parent_name = cls._get_parent_name(asset)
            resource_data = asset['resource']['data']
            # Remove unused proto representation of asset
            resource_data.pop('internal_data', None)
            asset_data = json.dumps(resource_data, sort_keys=True)
        elif 'iam_policy' in asset:
            content_type = 'iam_policy'
            parent_name = asset['name']
            asset_data = json.dumps(asset['iam_policy'], sort_keys=True)
        elif 'org_policy' in asset:
            content_type = 'org_policy'
            parent_name = asset['name']
            asset_data = json.dumps(asset['org_policy'], sort_keys=True)
            name = asset['org_policy'][0]['constraint']
        elif 'access_policy' in asset:
            content_type = 'access_policy'
            parent_name = asset['name']
            asset_data = json.dumps(asset['access_policy'], sort_keys=True)
            name = asset['access_policy']['name']
        elif 'access_level' in asset:
            content_type = 'access_level'
            access_level = asset[content_type]
            asset_data = json.dumps(access_level, sort_keys=True)
            name = access_level['name']
            parent_name = name.split('/accessLevels')[0]
        elif 'service_perimeter' in asset:
            content_type = 'service_perimeter'
            service_perimeter = asset[content_type]
            asset_data = json.dumps(service_perimeter, sort_keys=True)
            name = service_perimeter['name']
            parent_name = name.split('/servicePerimeters')[0]
        else:
            LOGGER.warning('Unparsable asset, no resource or iam policy: %s',
                           asset)
            return None

        return {
            'name': name or asset['name'],
            'parent_name': parent_name,
            'content_type': content_type,
            'asset_type': asset['asset_type'],
            'asset_data': asset_data.encode('utf-8'),
            'update_time': dateutil.parser.parse(asset['update_time'])
        }

    @classmethod
    def delete_all(cls, engine):
        """Deletes all rows from this table.

        Args:
            engine (object): db engine

        Returns:
            int: The number of rows deleted.

        Raises:
            Exception: Reraises any exception.
        """
        try:
            results = engine.execute(cls.__table__.delete())
            return results.rowcount
        except Exception as e:
            LOGGER.exception(e)
            raise

    # pylint: disable=too-many-return-statements
    @staticmethod
    def _get_parent_name(asset):
        """Determines the parent name from the resource data.

        Args:
            asset (dict): An Asset object.

        Returns:
            str: The parent name for the resource.
        """
        if 'parent' in asset['resource']:
            return asset['resource']['parent']

        if asset['asset_type'] == 'cloudkms.googleapis.com/KeyRing':
            # KMS KeyRings are parented by a location under a project, but
            # the location is not directly discoverable without iterating all
            # locations, so instead this creates an artificial parent at the
            # project level, which acts as an aggregated list of all keyrings
            # in all locations to fix this broken behavior.
            #
            # Strip locations/{LOCATION}/keyRings/{RING} off name to get the
            # parent project.
            return '/'.join(asset['name'].split('/')[:-4])

        elif asset['asset_type'] == 'dataproc.googleapis.com/Cluster':
            # Dataproc Clusters are parented by a region under a project, but
            # the region is not directly discoverable without iterating all
            # regions, so instead this creates an artificial parent at the
            # project level, which acts as an aggregated list of all clusters
            # in all regions to fix this broken behavior.
            #
            # Strip regions/{REGION}/clusters/{CLUSTER_NAME} off name to get the
            # parent project.
            return '/'.join(asset['name'].split('/')[:-4])

        elif (asset['asset_type'].startswith('appengine.googleapis.com/') or
              asset['asset_type'].startswith('bigquery.googleapis.com/') or
              asset['asset_type'].startswith('cloudkms.googleapis.com/') or
              asset['asset_type'].startswith('sqladmin.googleapis.com/') or
              asset['asset_type'].startswith('spanner.googleapis.com/')):
            # Strip off the last two segments of the name to get the parent
            return '/'.join(asset['name'].split('/')[:-2])

        elif asset['asset_type'] in ('k8s.io/Node', 'k8s.io/Namespace'):
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/nodes/test-node"
            #
            # Strip k8s/nodes/{NODE} off name to get the parent.
            #
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/namespaces/test-namespace"
            #
            # Strip k8s/namespaces/{NAMESPACE} off name to get the parent.
            return '/'.join(asset['name'].split('/')[:-3])

        elif asset['asset_type'] == 'k8s.io/Pod':
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/namespaces/
            # test-namespace/pods/test-pod"
            #
            # Strip pods/{POD} off name to get the parent.
            return '/'.join(asset['name'].split('/')[:-2])

        elif asset['asset_type'] in ('rbac.authorization.k8s.io/Role',
                                     'rbac.authorization.k8s.io/RoleBinding'):
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/namespaces/
            # test-namespace/rbac.authorization.k8s.io/roles/
            # extension-apiserver-authentication-reader"
            #
            # Strip rbac.authorization.k8s.io/roles/{ROLE} off name to get the
            # parent.
            #
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/namespaces/test-namespace/
            # rbac.authorization.k8s.io/rolebindings/
            # system:controller:bootstrap-signer"
            #
            # Strip rbac.authorization.k8s.io/rolebindings/{ROLEBINDING} off
            # name to get the parent.
            return '/'.join(asset['name'].split('/')[:-3])

        elif asset['asset_type'] in (
                'rbac.authorization.k8s.io/ClusterRole',
                'rbac.authorization.k8s.io/ClusterRoleBinding'):
            # Kubernetes ClusterRoles and ClusterRoleBindings are parented by a
            # k8s under a cluster, but the k8 is not directly discoverable
            # without iterating all k8s, so instead this creates an artificial
            # parent at the cluster level, which acts as an aggregated list of
            # all cluster roles and cluster role bindings in all k8s to fix this
            # broken behavior.
            #
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/rbac.authorization.k8s.io/
            # clusterroles/cloud-provider"
            #
            # Strip k8s/rbac.authorization.k8s.io/clusterroles/
            # {CLUSTERROLE} off name to get the parent.
            #
            # "name":"//container.googleapis.com/projects/test-project/zones/
            # us-central1-b/clusters/test-cluster/k8s/
            # rbac.authorization.k8s.io/clusterrolebindings/cluster-admin"
            #
            # Strip k8s/rbac.authorization.k8s.io/clusterrolebindings/
            # {CLUSTERROLEBINDING} off name to get the parent.
            return '/'.join(asset['name'].split('/')[:-4])

        # Known unparented asset types.
        if asset['asset_type'] not in CaiTemporaryStore.UNPARENTED_ASSETS:
            LOGGER.debug('Could not determine parent name for %s', asset)

        return ''


class CaiDataAccess(object):
    """Access to the CAI temporary store table."""

    @staticmethod
    def clear_cai_data(engine):
        """Deletes all temporary CAI data from the cai temporary table.

        Args:
            engine (object): Database engine.

        Returns:
            int: The number of rows deleted.
        """
        return CaiTemporaryStore.delete_all(engine)

    @staticmethod
    def populate_cai_data(data, engine):
        """Add assets from cai data dump into cai temporary table.

        Args:
            data (file): A file like object, line delimeted text dump of json
                data representing assets from Cloud Asset Inventory exportAssets
                API.
            engine (object): Database engine.

        Returns:
            int: The number of rows inserted
        """
        num_rows = 0
        cai_table_insert = CaiTemporaryStore.__table__.insert
        try:
            rows_total_length = 0
            rows = []
            for line in data:
                if not line:
                    continue
                row = CaiTemporaryStore.from_json(line.strip().encode())
                if row:
                    num_rows += 1
                    rows.append(row)
                    rows_total_length += sum(len(str(v)) for v in row.values())
                    if rows_total_length > MAX_ALLOWED_INSERT_SIZE * .9:
                        LOGGER.debug('Flushing %i rows to CAI table', len(rows))
                        engine.execute(cai_table_insert(), rows)
                        rows_total_length = 0
                        rows = []

            if rows:
                LOGGER.debug('Flushing remaining %i rows to CAI table',
                             len(rows))
                engine.execute(cai_table_insert(), rows)
        except SQLAlchemyError as e:
            LOGGER.error('Error populating CAI data: %s', e)
        return num_rows

    @staticmethod
    @retry(wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def iter_cai_assets(content_type, asset_type, parent_name, engine):
        """Iterate the objects in the cai temporary table.

        Retries query on exception up to 5 times.

        Args:
            content_type (ContentTypes): The content type to return.
            asset_type (str): The asset type to return.
            parent_name (str): The parent resource to iter children under.
            engine (object): Database engine.

        Yields:
            object: The content_type data for each resource.
        """
        base_query = CaiTemporaryStore.__table__.select()
        filters = [
            CaiTemporaryStore.parent_name == parent_name,
            CaiTemporaryStore.content_type == content_type,
            CaiTemporaryStore.asset_type == asset_type,
        ]
        for qry_filter in filters:
            base_query = base_query.where(qry_filter)

        # Sub-query used by the join to get the latest asset based on update_time
        sub_query_columns = [
            CaiTemporaryStore.name.label('name2'),
            CaiTemporaryStore.asset_type.label('asset_type2'),
            CaiTemporaryStore.content_type.label('content_type2'),
            func.max(CaiTemporaryStore.update_time).label('update_time_join')
        ]
        sub_query = CaiTemporaryStore.__table__.select().with_only_columns(sub_query_columns)
        sub_query = sub_query.group_by(CaiTemporaryStore.name)
        sub_query = sub_query.group_by(CaiTemporaryStore.asset_type)
        sub_query = sub_query.group_by(CaiTemporaryStore.content_type)

        join = CaiTemporaryStore.__table__.join(
            sub_query,
            and_(
                base_query.c.name == sub_query.c.name2,
                base_query.c.asset_type == sub_query.c.asset_type2,
                base_query.c.content_type == sub_query.c.content_type2,
                base_query.c.update_time == sub_query.c.update_time_join
            )
        )

        query = base_query.select_from(join)
        results = engine.execute(query)

        # Process results
        for row in results:
            yield CaiDataAccess._extract_asset_data(row)

    @staticmethod
    @retry(wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def fetch_cai_asset(content_type, asset_type, name, engine):
        """Returns a single resource from the cai temporary store.

        Retries query on exception up to 5 times.

        Args:
            content_type (ContentTypes): The content type to return.
            asset_type (str): The asset type to return.
            name (str): The resource to return.
            engine (object): Database engine.

        Returns:
            dict: The content data for the specified resource.
        """
        base_query = CaiTemporaryStore.__table__.select()
        filters = [
            CaiTemporaryStore.content_type == content_type,
            CaiTemporaryStore.asset_type == asset_type,
            CaiTemporaryStore.name == name,
        ]

        for qry_filter in filters:
            base_query = base_query.where(qry_filter)

        # Order by update time so that the latest asset is returned
        base_query.order_by(CaiTemporaryStore.update_time.desc())

        results = engine.execute(base_query)
        row = results.first()

        if not row:
            return {}, None

        return CaiDataAccess._extract_asset_data(row)

    @staticmethod
    def _extract_asset_data(row):
        """Extracts the data from the database row.

        Args:
            row (dict): Database row from select query.

        Returns:
            Tuple[dict, AssetMetadata]: The dict representation of the asset
                data and an Asset metadata along with it.
        """
        asset = json.loads(row['asset_data'])
        asset_metadata = AssetMetadata(cai_name=row['name'],
                                       cai_type=row['asset_type'])

        return asset, asset_metadata


def create_sqlite_db(threads=1):
    """Create and initialize a sqlite db engine for use as the CAI temp store.

    Args:
        threads (int): The number of threads to support. Pool size is set to 5
            greater than the number of threads, so that each thread can get its
            own connection to the temp database, with a few spare.
    Returns:
        Tuple[sqlalchemy.engine.Engine, str]: A tuple containing an engine
            object initialized to a temporary sqlite db file, and the path to
            the temporary file.
    """
    dbfile, tmpfile = tempfile.mkstemp('.db', 'forseti-cai-store-')
    pool_size = threads + 5
    try:
        engine = create_engine('sqlite:///{}'.format(tmpfile),
                               sqlite_enforce_fks=False,
                               pool_size=pool_size,
                               connect_args={'check_same_thread': False},
                               poolclass=SingletonThreadPool)
        _initialize(engine)
        return engine, tmpfile
    finally:
        os.close(dbfile)


def _initialize(engine):
    """Create all tables in the database if not existing.

    Args:
        engine (object): Database engine to operate on.
    """
    BASE.metadata.create_all(engine)
