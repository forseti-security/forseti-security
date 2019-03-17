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

import os
import time

import concurrent.futures
from googleapiclient import errors

from google.cloud.forseti.common.gcp_api import cloudasset
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.services.inventory.storage import CaiDataAccess

LOGGER = logger.get_logger(__name__)
CONTENT_TYPES = ['RESOURCE', 'IAM_POLICY']

# Any asset type referenced in cai_gcp_client.py needs to be added here.
DEFAULT_ASSET_TYPES = [
    'appengine.googleapis.com/Application',
    'appengine.googleapis.com/Service',
    'appengine.googleapis.com/Version',
    'bigquery.googleapis.com/Dataset',
    'cloudbilling.googleapis.com/BillingAccount',
    'cloudkms.googleapis.com/CryptoKey',
    'cloudkms.googleapis.com/CryptoKeyVersion',
    'cloudkms.googleapis.com/KeyRing',
    'cloudresourcemanager.googleapis.com/Folder',
    'cloudresourcemanager.googleapis.com/Organization',
    'cloudresourcemanager.googleapis.com/Project',
    'compute.googleapis.com/Autoscaler',
    'compute.googleapis.com/BackendBucket',
    'compute.googleapis.com/BackendService',
    'compute.googleapis.com/Disk',
    'compute.googleapis.com/Firewall',
    'compute.googleapis.com/ForwardingRule',
    'compute.googleapis.com/HealthCheck',
    'compute.googleapis.com/HttpHealthCheck',
    'compute.googleapis.com/HttpsHealthCheck',
    'compute.googleapis.com/Image',
    'compute.googleapis.com/Instance',
    'compute.googleapis.com/InstanceGroup',
    'compute.googleapis.com/InstanceGroupManager',
    'compute.googleapis.com/InstanceTemplate',
    'compute.googleapis.com/License',
    'compute.googleapis.com/Network',
    'compute.googleapis.com/Project',
    'compute.googleapis.com/Router',
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
    'iam.googleapis.com/ServiceAccount',
    'pubsub.googleapis.com/Subscription',
    'pubsub.googleapis.com/Topic',
    'spanner.googleapis.com/Database',
    'spanner.googleapis.com/Instance',
    'sqladmin.googleapis.com/Instance',
    'storage.googleapis.com/Bucket',
]


def load_cloudasset_data(session, config):
    """Export asset data from Cloud Asset API and load into storage.

    Args:
        session (object): Database session.
        config (object): Inventory configuration on server.

    Returns:
        int: The count of assets imported into the database, or None if there
            is an error.
    """
    # Start by ensuring that there is no existing CAI data in storage.
    _clear_cai_data(session)

    cloudasset_client = cloudasset.CloudAssetClient(
        config.get_api_quota_configs())
    imported_assets = 0

    root_resources = []
    if config.use_composite_root():
        root_resources.extend(config.get_composite_root_resources())
    else:
        root_resources.append(config.get_root_resource_id())

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        futures = []
        for root_id in root_resources:
            for content_type in CONTENT_TYPES:
                futures.append(executor.submit(_export_assets,
                                               cloudasset_client,
                                               config,
                                               root_id,
                                               content_type))

        for future in concurrent.futures.as_completed(futures):
            temporary_file = ''
            try:
                temporary_file = future.result()
                if not temporary_file:
                    return _clear_cai_data(session)

                LOGGER.debug('Importing Cloud Asset data from %s to database.',
                             temporary_file)
                with open(temporary_file, 'r') as cai_data:
                    rows = CaiDataAccess.populate_cai_data(cai_data, session)
                    imported_assets += rows
                    LOGGER.info('%s assets imported to database.', rows)
            finally:
                if temporary_file:
                    os.unlink(temporary_file)

    return imported_assets


def _export_assets(cloudasset_client, config, root_id, content_type):
    """Worker function for exporting assets and downloading dump from GCS.

    Args:
        cloudasset_client (CloudAssetClient): CloudAsset API client interface.
        config (object): Inventory configuration on server.
        root_id (str): The name of the parent resource to export assests under.
        content_type (ContentTypes): The content type to export.

    Returns:
        str: The path to the temporary file downloaded from GCS or None on
            error.
    """
    asset_types = config.get_cai_asset_types()
    if not asset_types:
        asset_types = DEFAULT_ASSET_TYPES
    timeout = config.get_cai_timeout()

    timestamp = int(time.time())
    export_path = _get_gcs_path(config.get_cai_gcs_path(),
                                content_type,
                                root_id,
                                timestamp)

    try:
        LOGGER.info('Starting Cloud Asset export for %s under %s to GCS object '
                    '%s.', content_type, root_id, export_path)
        if asset_types:
            LOGGER.info('Limiting export to the following asset types: %s',
                        asset_types)

        results = cloudasset_client.export_assets(root_id,
                                                  export_path,
                                                  content_type=content_type,
                                                  asset_types=asset_types,
                                                  blocking=True,
                                                  timeout=timeout)
        LOGGER.debug('Cloud Asset export for %s under %s to GCS '
                     'object %s completed, result: %s.',
                     content_type, root_id, export_path, results)
    except api_errors.ApiExecutionError as e:
        LOGGER.warn('API Error getting cloud asset data: %s', e)
        return None
    except api_errors.OperationTimeoutError as e:
        LOGGER.warn('Timeout getting cloud asset data: %s', e)
        return None
    except ValueError as e:
        LOGGER.warn('Invalid root resource id: %s', e)
        return None

    if 'error' in results:
        LOGGER.error('Export of cloud asset data had an error, aborting: '
                     '%s', results)
        return None

    try:
        LOGGER.debug('Downloading Cloud Asset data from GCS to disk.')
        return file_loader.copy_file_from_gcs(export_path)
    except errors.HttpError as e:
        LOGGER.warn('Download of CAI dump from GCS failed: %s', e)
        return None


def _clear_cai_data(session):
    """Clear CAI data from storage.

    Args:
        session (object): Database session.
    """
    LOGGER.debug('Deleting Cloud Asset data from database.')
    count = CaiDataAccess.clear_cai_data(session)
    LOGGER.debug('%s assets deleted from database.', count)
    return None


def _get_gcs_path(base_path, content_type, root_id, timestamp):
    """Generate a GCS object path for CAI dump.

    Args:
        base_path (str): The GCS bucket, starting with 'gs://'.
        content_type (str): The Cloud Asset content type for this export.
        root_id (str): The root resource ID for this export.
        timestamp (int): The timestamp for this export.

    Returns:
        str: The full path to a GCS object to store export the data to.
    """
    return '{}/{}-{}-{}.dump'.format(base_path,
                                     root_id.replace('/', '-'),
                                     content_type.lower(),
                                     timestamp)
