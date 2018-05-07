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


from google.cloud.forseti.common.util import file_uploader
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import base_notification


LOGGER = logger.get_logger(__name__)


class GcsViolations(base_notification.BaseNotification):
    """Upload violations to GCS."""

    def run(self):
        """Generate the temporary (CSV xor JSON) file and upload to GCS."""
        if not self.notification_config['gcs_path'].startswith('gs://'):
            return

        data_format = self.notification_config.get('data_format', 'csv')
        if data_format not in self.supported_data_formats:
            raise base_notification.InvalidDataFormatError(
                'GCS uploader', data_format)

        if data_format == 'csv':
            gcs_upload_path = '{}/{}'.format(
                self.notification_config['gcs_path'],
                self._get_output_filename(
                    string_formats.VIOLATION_CSV_FMT))
            file_uploader.upload_csv(
                'violations', self.violations, gcs_upload_path)
        else:
            gcs_upload_path = '{}/{}'.format(
                self.notification_config['gcs_path'],
                self._get_output_filename(
                    string_formats.VIOLATION_JSON_FMT))
            file_uploader.upload_json(self.violations, gcs_upload_path)
