# Copyright 2018 The Forseti Security Authors. All rights reserved.
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

"""Forseti Inventory Cloud Asset API integration."""
import codecs
from collections import deque
import os
import threading

import concurrent.futures
from googleapiclient import errors

from google.cloud.forseti.common.gcp_api import cloudasset
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.inventory import cai_temporary_storage

LOGGER = logger.get_logger(__name__)
CONTENT_TYPES = ['RESOURCE', 'IAM_POLICY']

# Any asset type referenced in cai_gcp_client.py needs to be added here.
DEFAULT_ASSET_TYPES = [
    'appengine.googleapis.com/Application',
    'appengine.googleapis.com/Service',
    'appengine.googleapis.com/Version',
    'bigquery.googleapis.com/Dataset',
    'bigquery.googleapis.com/Table',
    'bigtableadmin.googleapis.com/Cluster',
    'bigtableadmin.googleapis.com/Instance',
    'bigtableadmin.googleapis.com/Table',
    'cloudbilling.googleapis.com/BillingAccount',
    'cloudkms.googleapis.com/CryptoKey',
    'cloudkms.googleapis.com/CryptoKeyVersion',
    'cloudkms.googleapis.com/KeyRing',
    'cloudresourcemanager.googleapis.com/Folder',
    'cloudresourcemanager.googleapis.com/Organization',
    'cloudresourcemanager.googleapis.com/Project',
    'compute.googleapis.com/Address',
    'compute.googleapis.com/Autoscaler',
    'compute.googleapis.com/BackendBucket',
    'compute.googleapis.com/BackendService',
    'compute.googleapis.com/Disk',
    'compute.googleapis.com/Firewall',
    'compute.googleapis.com/ForwardingRule',
    'compute.googleapis.com/GlobalAddress',
    'compute.googleapis.com/GlobalForwardingRule',
    'compute.googleapis.com/HealthCheck',
    'compute.googleapis.com/HttpHealthCheck',
    'compute.googleapis.com/HttpsHealthCheck',
    'compute.googleapis.com/Image',
    'compute.googleapis.com/Instance',
    'compute.googleapis.com/InstanceGroup',
    'compute.googleapis.com/InstanceGroupManager',
    'compute.googleapis.com/InstanceTemplate',
    'compute.googleapis.com/Interconnect',
    'compute.googleapis.com/InterconnectAttachment',
    'compute.googleapis.com/License',
    'compute.googleapis.com/Network',
    'compute.googleapis.com/Project',
    'compute.googleapis.com/RegionBackendService',
    'compute.googleapis.com/RegionDisk',
    'compute.googleapis.com/Router',
    'compute.googleapis.com/SecurityPolicy',
    'compute.googleapis.com/Snapshot',
    'compute.googleapis.com/SslCertificate',
    'compute.googleapis.com/Subnetwork',
    'compute.googleapis.com/TargetHttpProxy',
    'compute.googleapis.com/TargetHttpsProxy',
    'compute.googleapis.com/TargetInstance',
    'compute.googleapis.com/TargetPool',
    'compute.googleapis.com/TargetSslProxy',
    'compute.googleapis.com/TargetTcpProxy',
    'compute.googleapis.com/TargetVpnGateway',
    'compute.googleapis.com/UrlMap',
    'compute.googleapis.com/VpnTunnel',
    'container.googleapis.com/Cluster',
    'dataproc.googleapis.com/Cluster',
    'dns.googleapis.com/ManagedZone',
    'dns.googleapis.com/Policy',
    'iam.googleapis.com/Role',
    'k8s.io/Namespace',
    'k8s.io/Node',
    'k8s.io/Pod',
    'iam.googleapis.com/ServiceAccount',
    'pubsub.googleapis.com/Subscription',
    'pubsub.googleapis.com/Topic',
    'rbac.authorization.k8s.io/ClusterRole',
    'rbac.authorization.k8s.io/ClusterRoleBinding',
    'rbac.authorization.k8s.io/Role',
    'rbac.authorization.k8s.io/RoleBinding',
    'spanner.googleapis.com/Database',
    'spanner.googleapis.com/Instance',
    'sqladmin.googleapis.com/Instance',
    'storage.googleapis.com/Bucket',
]


class StreamError(Exception):
    """Raised for errors streaming results from GCS to local DB."""


def _download_cloudasset_data(config, inventory_index_id):
    """Download cloud asset data.

    Args:
        config (InventoryConfig): Inventory config.
        inventory_index_id (int): The inventory index ID for this export.

    Yields:
        str: GCS path of the cloud asset file.
    """
    root_resources = []
    if config.use_composite_root():
        root_resources.extend(config.get_composite_root_resources())
    else:
        root_resources.append(config.get_root_resource_id())
    cloudasset_client = cloudasset.CloudAssetClient(
        config.get_api_quota_configs())
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        for root_id in root_resources:
            for content_type in CONTENT_TYPES:
                futures.append(executor.submit(_export_assets,
                                               cloudasset_client,
                                               config,
                                               root_id,
                                               content_type,
                                               inventory_index_id))

        for future in concurrent.futures.as_completed(futures):
            yield future.result()


def load_cloudasset_data(engine, config, inventory_index_id):
    """Export asset data from Cloud Asset API and load into storage.

    Args:
        engine (object): Database engine.
        config (InventoryConfig): Inventory configuration on server.
        inventory_index_id (int): The inventory index ID for this export.

    Returns:
        int: The count of assets imported into the database, or None if there
            is an error.
    """
    cai_gcs_dump_paths = config.get_cai_dump_file_paths()

    storage_client = storage.StorageClient()
    imported_assets = 0

    if not cai_gcs_dump_paths:
        # Dump file paths not specified, download the dump files instead.
        cai_gcs_dump_paths = _download_cloudasset_data(
            config,
            inventory_index_id)

    for gcs_path in cai_gcs_dump_paths:
        try:
            assets = _stream_gcs_to_database(gcs_path,
                                             engine,
                                             storage_client)
            imported_assets += assets
        except StreamError as e:
            LOGGER.error('Error streaming data from GCS to Database: %s', e)
            return _clear_cai_data(engine)

    # Each worker's imported asset count is appended to the deque, sum them all
    # to get total imported assets.
    LOGGER.info('%i assets imported to database.', imported_assets)

    # Optimize the new database before returning
    engine.execute('pragma optimize;')
    return imported_assets


def _stream_cloudasset_worker(cai_data, engine, output_queue):
    """Worker to stream data from GCS into sqlite temporary table.

    Args:
        cai_data (file): An open file like pipe.
        engine (sqlalchemy.engine.Engine): Database engine to write data to.
        output_queue (collections.deque): A queue storing the results of this
            thread.
    """
    # Codecs transforms the raw byte stream into an iterable of lines.
    cai_iter = codecs.getreader('utf-8')(cai_data)
    rows = cai_temporary_storage.CaiDataAccess.populate_cai_data(
        cai_iter, engine)
    LOGGER.info('%s assets imported to database.', rows)
    output_queue.append(rows)


def _stream_gcs_to_database(gcs_object, engine, storage_client):
    """Stream data from GCS into a local database using pipes.

    Args:
        gcs_object (str): The full path to the GCS object to read.
        engine (sqlalchemy.engine.Engine): The db engine to store the data in.
        storage_client (storage.StorageClient): The storage client to use to
            download data from GCS.

    Returns:
        int: The number of rows stored in the database.

    Raises:
        StreamError: Raised on any errors streaming data from GCS.
    """
    if not gcs_object:
        raise StreamError('GCS Object name not defined.')

    LOGGER.info('Importing Cloud Asset data from %s to database.',
                gcs_object)

    # Use a deque to store the output of the worker threads as appends are
    # atomic and thread safe.
    imported_rows = deque()

    # Create a pair of connected pipe objects to stream the data from
    # GCS into the sqlite database without having to download the data
    # to the local system first.
    read_pipe, write_pipe = os.pipe()
    # Create file like objects for each pipe
    read_file = os.fdopen(read_pipe, mode='rb')
    write_file = os.fdopen(write_pipe, mode='wb')
    # Create a separate thread for writing the data to sqlite, reading
    # from the input side of the pipe.
    worker = threading.Thread(target=_stream_cloudasset_worker,
                              args=(read_file, engine, imported_rows))
    worker.start()

    try:
        # Stream data from GCS into the output side of the pip
        storage_client.download(full_bucket_path=gcs_object,
                                output_file=write_file)
    except errors.HttpError as e:
        LOGGER.error('Could not download %s from GCS: %s',
                     gcs_object, e)
        raise StreamError('Could not download %s from GCS : %s' %
                          (gcs_object, e))
    finally:
        # Close the write side of the pipe so the read side will know
        # when it reaches EOF and the tread will return.
        write_file.close()

        # Wait for thread to complete before continuing
        worker.join()

        # Don't leak resources, ensure both sides of pipe are closed.
        read_file.close()

    return imported_rows.popleft()


def _export_assets(
        cloudasset_client, config, root_id, content_type, inventory_index_id):
    """Worker function for exporting assets and downloading dump from GCS.

    Args:
        cloudasset_client (CloudAssetClient): CloudAsset API client interface.
        config (object): Inventory configuration on server.
        root_id (str): The name of the parent resource to export assests under.
        content_type (ContentTypes): The content type to export.
        inventory_index_id (int): The inventory index ID for this export.

    Returns:
        str: The path to the GCS object created by the CloudAsset API.

    Raises:
        ValueError: Raised if the server configuration for CAI export is
            invalid.
    """
    asset_types = config.get_cai_asset_types()
    if not asset_types:
        asset_types = DEFAULT_ASSET_TYPES
    timeout = config.get_cai_timeout()

    export_path = _get_gcs_path(config.get_cai_gcs_path(),
                                content_type,
                                root_id,
                                inventory_index_id)

    try:
        LOGGER.info('Starting Cloud Asset export for %s under %s to GCS object '
                    '%s.', content_type, root_id, export_path)
        if asset_types:
            LOGGER.info('Limiting export to the following asset types: %s',
                        asset_types)
        output_config = cloudasset_client.build_gcs_object_output(export_path)
        try:
            results = cloudasset_client.export_assets(
                root_id,
                output_config=output_config,
                content_type=content_type,
                asset_types=asset_types,
                blocking=True,
                timeout=timeout)
        except api_errors.ApiExecutionError as e:
            if e.http_error.resp.status == 400:
                LOGGER.warning('Bad request with unsupported resource types '
                               'sent to CAI for %s under %s. Exporting all '
                               'resources for Cloud Asset export.',
                               content_type, root_id)
                results = cloudasset_client.export_assets(
                    root_id,
                    output_config=output_config,
                    content_type=content_type,
                    asset_types=[],
                    blocking=True,
                    timeout=timeout)
            else:
                LOGGER.warning('API Error getting cloud asset data: %s', e)
                return None
        LOGGER.debug('Cloud Asset export for %s under %s to GCS '
                     'object %s completed, result: %s.',
                     content_type, root_id, export_path, results)
    except api_errors.ApiExecutionError as e:
        LOGGER.warning('API Error getting cloud asset data: %s', e)
        return None
    except api_errors.OperationTimeoutError as e:
        LOGGER.warning('Timeout getting cloud asset data: %s', e)
        return None
    except ValueError as e:
        LOGGER.error('Invalid configuration, could not export assets from CAI: '
                     '%s', e)
        raise

    if 'error' in results:
        LOGGER.error('Export of cloud asset data had an error, aborting: '
                     '%s', results)
        return None

    return export_path


def _clear_cai_data(engine):
    """Clear CAI data from storage.

    Args:
        engine (object): Database engine.
    """
    LOGGER.debug('Deleting Cloud Asset data from database.')
    count = cai_temporary_storage.CaiDataAccess.clear_cai_data(engine)
    LOGGER.debug('%s assets deleted from database.', count)
    return None


def _get_gcs_path(base_path, content_type, root_id, inventory_index_id):
    """Generate a GCS object path for CAI dump.

    Args:
        base_path (str): The GCS bucket, starting with 'gs://'.
        content_type (str): The Cloud Asset content type for this export.
        root_id (str): The root resource ID for this export.
        inventory_index_id (int): The inventory index ID for this export.

    Returns:
        str: The full path to a GCS object to store export the data to.
    """
    return '{}/{}-{}-{}.dump'.format(base_path,
                                     root_id.replace('/', '-'),
                                     content_type.lower(),
                                     inventory_index_id)
