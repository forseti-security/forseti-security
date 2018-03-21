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

"""Upload violations to GCS."""


from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import base_notification


LOGGER = logger.get_logger(__name__)


class GcsViolations(base_notification.BaseNotification):
    """Upload violations to GCS."""

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            str: The output filename for the violations CSV file.
        """
        now_utc = date_time.get_utc_now_datetime()
        output_timestamp = now_utc.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)
        output_filename = string_formats.VIOLATION_JSON_FMT.format(
            self.resource, self.cycle_timestamp, output_timestamp)
        return output_filename

    def run(self):
        """Generate the temporary CSV file and upload to GCS."""
        with csv_writer.write_csv(resource_name='violations',
                                  data=self.violations,
                                  write_header=True) as csv_file:
            LOGGER.info('CSV filename: %s', csv_file.name)

            gcs_upload_path = '{}/{}'.format(
                self.notification_config['gcs_path'],
                self._get_output_filename())

            if gcs_upload_path.startswith('gs://'):
                storage_client = storage.StorageClient()
                storage_client.put_text_file(
                    '/tmp/%s' % csv_file.name, gcs_upload_path)
