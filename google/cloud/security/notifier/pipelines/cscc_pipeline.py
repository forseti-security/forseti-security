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

"""Upload violations to GCS bucket for CSCC integration."""

import tempfile

from datetime import datetime

from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser


LOGGER = log_util.get_logger(__name__)

OUTPUT_FILENAME = 'forseti_findings_{}.json'


class CsccPipeline(object):
    """Upload violations to GCS bucket as findings."""

    @staticmethod
    def _transform_to_findings(violations):
        """Transform forseti violations to findings format.

        Args:
            violations (dict): Violations to be uploaded as findings.

        Returns:
            list: violations in findings format; each violation is a dict.
        """
        findings = []
        for violation in violations:
            finding = {
                'finding_id': violation.get('violation_hash'),
                'finding_summary': violation.get('rule_name'),
                'finding_source_id': 'FORSETI',
                'finding_category': violation.get('violation_type'),
                'finding_asset_ids': violation.get('resource_id'),
                'finding_time_event': violation.get('created_at_datetime'),
                'finding_callback_url': None,
                'finding_properties': {
                    'violation_data': violation.get('violation_data'),
                    'resource_type': violation.get('resource_type'),
                    'resource_id': violation.get('resource_id'),
                    'rule_index': violation.get('rule_index'),
                    'inventory_index_id': violation.get('inventory_timestamp'),
                }
            }
            findings.append(finding)

        return findings

    @staticmethod
    def _get_output_filename():
        """Create the output filename.

        Returns:
            str: The output filename for the violations json.
        """
        now_utc = datetime.utcnow()
        output_timestamp = now_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
        return OUTPUT_FILENAME.format(output_timestamp)

    def run(self, violations, gcs_path):
        """Generate the temporary json file and upload to GCS.

        Args:
            violations (dict): Violations to be uploaded as findings.
            gcs_path (str): The GCS bucket to upload the findings.
        """
        LOGGER.info('Running CSCC findings notification.')
        findings = self._transform_to_findings(violations)

        with tempfile.NamedTemporaryFile() as tmp_violations:
            tmp_violations.write(parser.json_stringify(findings))
            tmp_violations.flush()

            gcs_upload_path = '{}/{}'.format(
                gcs_path,
                self._get_output_filename())

            if gcs_upload_path.startswith('gs://'):
                storage_client = storage.StorageClient()
                storage_client.put_text_file(
                    tmp_violations.name, gcs_upload_path)
        LOGGER.info('Completed CSCC findings notification.')
