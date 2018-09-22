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

"""Forseti Inventory Cloud Asset API integration."""

import os
import time

from googleapiclient import errors

from google.cloud.forseti.common.gcp_api import cloudasset
from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.util import file_loader
from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)
CONTENT_TYPES = ['RESOURCE', 'IAM_POLICY']


def load_cloudasset_data(storage,
                         config):
    """Export asset data from Cloud Asset API and load into storage.

    Args:
        storage (object): Storage implementation to use.
        config (object): Inventory configuration on server

    Returns:
        int: The count of assets imported into the database, or None if there
            is an error.
    """
    client_config = config.get_api_quota_configs()
    root_id = config.get_root_resource_id()

    # Start by ensuring that there is no existing CAI data in storage.
    _clear_cai_data(storage)

    cloudasset_client = cloudasset.CloudAssetClient(client_config)
    imported_assets = 0
    timestamp = int(time.time())

    for content_type in CONTENT_TYPES:
        export_path = _get_gcs_path(config.get_cai_gcs_path(),
                                    content_type,
                                    root_id,
                                    timestamp)
        try:
            LOGGER.info('Starting Cloud Asset export for %s under %s to '
                        'GCS object %s.', content_type, root_id, export_path)
            results = cloudasset_client.export_assets(root_id,
                                                      export_path,
                                                      content_type=content_type,
                                                      blocking=True,
                                                      timeout=3600)
            LOGGER.debug('Cloud Asset export for %s under %s to GCS '
                         'object %s completed, result: %s.',
                         content_type, root_id, export_path, results)
        except api_errors.ApiExecutionError as e:
            LOGGER.warn('API Error getting cloud asset data: %s', e)
            return _clear_cai_data(storage)
        except api_errors.OperationTimeoutError as e:
            LOGGER.warn('Timeout getting cloud asset data: %s', e)
            return _clear_cai_data(storage)

        if 'error' in results:
            LOGGER.error('Export of cloud asset data had an error, aborting: '
                         '%s', results)
            return _clear_cai_data(storage)

        temporary_file = None
        try:
            LOGGER.debug('Downloading Cloud Asset data from GCS to disk.')
            temporary_file = file_loader.copy_file_from_gcs(export_path)
            LOGGER.debug('Importing Cloud Asset data from %s to database.',
                         temporary_file)
            with open(temporary_file, 'r') as cai_data:
                rows = storage.populate_cai_data(cai_data)
                imported_assets += rows
                LOGGER.info('%s assets imported to database.', rows)
        except errors.HttpError as e:
            LOGGER.warn('Download of CAI dump from GCS failed: %s', e)
            return _clear_cai_data(storage)
        finally:
            if temporary_file:
                os.unlink(temporary_file)

    return imported_assets


def _clear_cai_data(storage):
    """Clear CAI data from storage.

    Args:
        storage (object): Storage implementation to use.
    """
    LOGGER.debug('Deleting Cloud Asset data from database.')
    count = storage.clear_cai_data()
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
