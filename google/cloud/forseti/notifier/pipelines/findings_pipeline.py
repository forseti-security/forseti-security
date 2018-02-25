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

"""Upload violations to GCS bucket as Findings."""

import tempfile

from datetime import datetime

# pylint: disable=line-too-long
from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser
from google.cloud.forseti.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long


LOGGER = logger.get_logger(__name__)

OUTPUT_FILENAME = 'forseti_findings_{}.json'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


class FindingsPipeline(bnp.BaseNotificationPipeline):
    """Upload violations to GCS bucket findings."""

    def _transform_to_findings(self, violations):
        """Transform forseti violations to findings format.

        Args:
            violations (dict): Violations to be uploaded as findings.

        Returns:
            list: violations in findings format.
        """
        findings = []
        for violation in violations:
            finding = {
                'finding_id': 'violation_hash',
                'finding_summary': violation.get('rule_name'),
                'finding_source_id': 'FORSETI',
                'finding_category': violation.get('violation_type'),
                'finding_asset_ids': violation.get('full_name'),
                'finding_time_event': 'violation_timestamp',
                'finding_callback_url': None,
                'finding_properties': {
                    'violation_data': violation.get('violation_data'),
                    'resource_type': violation.get('resource_type'),
                    'resource_id': violation.get('resource_id'),
                    'rule_index': violation.get('rule_index'),
                    'inventory_index_id': violation.get('inventory_index_id'),
                    'inventory_data': violation.get('inventory_data')
                }
            }
            findings.append(finding)    
        return findings

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            str: The output filename for the violations json.
        """
        now_utc = datetime.utcnow()
        output_timestamp = now_utc.strftime(OUTPUT_TIMESTAMP_FMT)
        return OUTPUT_FILENAME.format(output_timestamp)

    def run(self, violations):
        """Generate the temporary json file and upload to GCS.

        Args:
            violations (dict): Violations to be uploaded as findings.
        """
        findings = self._transform_to_findings(violations)

        with tempfile.NamedTemporaryFile() as tmp_violations:
            tmp_violations.write(parser.json_stringify(findings))
            tmp_violations.flush()

            gcs_upload_path = '{}/{}'.format(
                self.pipeline_config['gcs_path'],
                self._get_output_filename())

            if gcs_upload_path.startswith('gs://'):
                storage_client = storage.StorageClient()
                storage_client.put_text_file(
                    tmp_violations.name, gcs_upload_path)
