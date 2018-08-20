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

"""Utility functions for file uploads."""


import tempfile

from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.gcp_api.storage import StorageClient
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser


LOGGER = logger.get_logger(__name__)


def upload_json(data, gcs_upload_path):
    """Upload data in json format.

    Args:
        data (dict): the data to upload
        gcs_upload_path (string): the GCS upload path.
    """
    try:
        with tempfile.NamedTemporaryFile() as tmp_data:
            tmp_data.write(parser.json_stringify(data))
            tmp_data.flush()
            storage_client = StorageClient()
            storage_client.put_text_file(tmp_data.name, gcs_upload_path)
    except Exception:  # pylint: disable=broad-except
        LOGGER.exception('Unable to upload json document to bucket %s:\n%s',
                         gcs_upload_path, data)


def upload_csv(resource_name, data, gcs_upload_path):
    """Upload data in csv format.

    Args:
        resource_name (str): what kind of CSV file are we creating?
        data (dict): the data to upload
        gcs_upload_path (string): the GCS upload path.
    """
    try:
        with csv_writer.write_csv(resource_name, data, True) as csv_file:
            LOGGER.info('CSV filename: %s', csv_file.name)
            storage_client = StorageClient()
            storage_client.put_text_file(csv_file.name, gcs_upload_path)
    except Exception:  # pylint: disable=broad-except
        LOGGER.exception('Unable to upload csv document to bucket %s:\n%s\n%s',
                         gcs_upload_path, data, resource_name)
