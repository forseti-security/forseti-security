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

"""Upload inventory summary to GCS."""

import tempfile

from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers.base_notification import (
    InvalidDataFormatError)


LOGGER = logger.get_logger(__name__)


class GcsInvSummary(object):
    """Upload inventory summary to GCS."""

    def __init__(self, inv_index_id, inv_summary, notifier_config):
        """Initialization.

        Args:
            inv_index_id (str): Inventory index id.
            inv_summary (dict): Inventory summary data.
            notifier_config (dict): the configuration for *this* notifier
        """
        self.inv_index_id = inv_index_id
        self.inv_summary = inv_summary
        self.notifier_config = notifier_config

    def _get_output_filename(self, filename_template):
        """Create the output filename.

        Args:
            filename_template (string): template to use for the output filename

        Returns:
            str: The output filename for the inventory summary file.
        """
        utc_now_datetime = date_time.get_utc_now_datetime()
        output_timestamp = utc_now_datetime.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)

        return filename_template.format(self.inv_index_id, output_timestamp)

    def _upload_json(self, gcs_upload_path):
        """Upload inventory summary in json format.

        Args:
            gcs_upload_path (string): the GCS upload path.
        """
        with tempfile.NamedTemporaryFile() as tmp_violations:
            tmp_violations.write(parser.json_stringify(self.inv_summary))
            tmp_violations.flush()
            storage_client = storage.StorageClient()
            storage_client.put_text_file(tmp_violations.name, gcs_upload_path)

    def _upload_csv(self, gcs_upload_path):
        """Upload inventory summary in csv format.

        Args:
            gcs_upload_path (string): the GCS upload path.
        """
        with csv_writer.write_csv(resource_name='inv_summary',
                                  data=self.inv_summary,
                                  write_header=True) as csv_file:
            LOGGER.info('CSV filename: %s', csv_file.name)
            storage_client = storage.StorageClient()
            storage_client.put_text_file(csv_file.name, gcs_upload_path)

    def run(self):
        """Generate the temporary (CSV xor JSON) file and upload to GCS."""
        if not self.notifier_config['gcs_path'].startswith('gs://'):
            return

        data_format = self.notifier_config.get('data_format', 'csv')
        if data_format not in self.supported_data_formats:
            raise InvalidDataFormatError('GCS uploader', data_format)

        if data_format == 'csv':
            gcs_upload_path = '{}/{}'.format(
                self.notifier_config['gcs_path'],
                self._get_output_filename(string_formats.INV_SUMMARY_CSV_FMT))
            self._upload_csv(gcs_upload_path)
        else:
            gcs_upload_path = '{}/{}'.format(
                self.notifier_config['gcs_path'],
                self._get_output_filename(string_formats.INV_SUMMARY_JSON_FMT))
            self._upload_json(gcs_upload_path)
