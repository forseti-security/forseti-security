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

import tempfile

from datetime import datetime

# pylint: disable=line-too-long
from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)

VIOLATIONS_JSON_FMT = 'violations.{}.{}.{}.json'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


class GcsViolationsPipeline(bnp.BaseNotificationPipeline):
    """Upload violations to GCS."""

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            str: The output filename for the violations json.
        """
        now_utc = datetime.utcnow()
        output_timestamp = now_utc.strftime(OUTPUT_TIMESTAMP_FMT)
        output_filename = VIOLATIONS_JSON_FMT.format(self.resource,
                                                     self.cycle_timestamp,
                                                     output_timestamp)
        return output_filename

    def run(self):
        """Generate the temporary json file and upload to GCS."""
        with tempfile.NamedTemporaryFile() as tmp_violations:
            tmp_violations.write(parser.json_stringify(
                                    self._filter_only_new(self.violations)))
            tmp_violations.flush()

            gcs_upload_path = '{}/{}'.format(
                self.pipeline_config['gcs_path'],
                self._get_output_filename())

            if gcs_upload_path.startswith('gs://'):
                storage_client = storage.StorageClient()
                storage_client.put_text_file(
                    tmp_violations.name, gcs_upload_path)
