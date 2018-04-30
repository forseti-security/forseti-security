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

from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import string_formats


LOGGER = logger.get_logger(__name__)


class CsccNotifier(object):
    """Upload violations to GCS bucket as CSCC findings."""

    def __init__(self, inv_index_id):
        """`Findingsnotifier` initializer.

        Args:
            inv_index_id (str): inventory index ID
        """
        self.inv_index_id = inv_index_id

    def _transform_to_findings(self, violations):
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
                'finding_asset_ids': violation.get('full_name'),
                'finding_time_event': violation.get('created_at_datetime'),
                'finding_callback_url': None,
                'finding_properties': {
                    'inventory_index_id': self.inv_index_id,
                    'resource_data': violation.get('resource_data'),
                    'resource_id': violation.get('resource_id'),
                    'resource_type': violation.get('resource_type'),
                    'rule_index': violation.get('rule_index'),
                    'scanner_index_id': violation.get('scanner_index_id'),
                    'violation_data': violation.get('violation_data')
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
        now_utc = date_time.get_utc_now_datetime()
        output_timestamp = now_utc.strftime(
            string_formats.TIMESTAMP_TIMEZONE)
        return string_formats.CSCC_FINDINGS_FILENAME.format(output_timestamp)

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
