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

from google.cloud.forseti.common.gcp_api import errors as api_errors
from google.cloud.forseti.common.gcp_api import securitycenter
from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import string_formats


LOGGER = logger.get_logger(__name__)


class CsccNotifier(object):
    """Send violations to CSCC via API or via GCS bucket."""

    def __init__(self, inv_index_id):
        """`Findingsnotifier` initializer.

        # TODO: Find out why the InventoryConfig is empty.

        Args:
            inv_index_id (str): inventory index ID
        """
        self.inv_index_id = inv_index_id

    def _transform_for_gcs(self, violations, gcs_upload_path):
        """Transform forseti violations to GCS findings format.

        Args:
            violations (dict): Violations to be uploaded as findings.
            gcs_upload_path (str): bucket and filename where the violations
                will be outputted on GCS

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
                'finding_callback_url': gcs_upload_path,
                'finding_properties': {
                    'db_source': 'table:{}/id:{}'.format(
                        'violations', violation.get('id')),
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

    def _send_findings_to_gcs(self, violations, gcs_path):
        """Send violations to CSCC via upload to GCS (legacy mode).
        Args:
            violations (dict): Violations to be uploaded as findings.
            gcs_path (str): The GCS bucket to upload the findings.
        """
        LOGGER.info('Legacy mode detected - writing findings to GCS.')

        gcs_upload_path = '{}/{}'.format(gcs_path, self._get_output_filename())

        findings = self._transform_for_gcs(violations, gcs_upload_path)

        with tempfile.NamedTemporaryFile() as tmp_violations:
            tmp_violations.write(parser.json_stringify(findings))
            tmp_violations.flush()

            if gcs_upload_path.startswith('gs://'):
                storage_client = storage.StorageClient()
                storage_client.put_text_file(
                    tmp_violations.name, gcs_upload_path)
        return

    def _transform_for_api(self, violations):
        """Transform forseti violations to findings for CSCC API.

        Args:
            violations (dict): Violations to be sent to CSCC as findings.

        Returns:
            list: violations in findings format; each violation is a dict.
        """
        findings = []
        for violation in violations:
            finding = {
                # CSCC can't accept the full hash, so this must be shortened.
                'id': violation.get('violation_hash')[:32],
                'assetIds': [
                    violation.get('full_name')
                ],
                'eventTime': violation.get('created_at_datetime'),
                'properties': {
                    'db_source': 'table:{}/id:{}'.format(
                        'violations', violation.get('id')),
                    'inventory_index_id': self.inv_index_id,
                    'resource_data': violation.get('resource_data'),
                    'resource_id': violation.get('resource_id'),
                    'resource_type': violation.get('resource_type'),
                    'rule_index': violation.get('rule_index'),
                    'scanner_index_id': violation.get('scanner_index_id'),
                    'violation_data': violation.get('violation_data')
                },
                'source_id': 'FORSETI',
                'category': violation.get('rule_name')
            }
            findings.append(finding)
        return findings

    def _send_findings_to_cscc(self, violations, organization_id):
        """Send violations to CSCC directly via the CSCC API.

        Args:
            violations (dict): Violations to be uploaded as findings.
            organization_id (str): The id prefixed with 'organizations/'.
        """
        findings = self._transform_for_api(violations)

        client = securitycenter.SecurityCenterClient()

        for finding in findings:
            LOGGER.debug('Creating finding CSCC:\n%s.', finding)
            try:
                client.create_finding(organization_id, finding)
                LOGGER.debug('Successfully created finding in CSCC:\n%s',
                             finding)
            except api_errors.ApiExecutionError:
                LOGGER.exception('Encountered CSCC API error.')
                continue
        return

    def run(self, violations, gcs_path, mode, organization_id):
        """Generate the temporary json file and upload to GCS.

        Args:
            violations (dict): Violations to be uploaded as findings.
            gcs_path (str): The GCS bucket to upload the findings.
            mode (str): The mode in which to send the CSCC notification.
            organization_id (str): The id of the organization.
        """
        LOGGER.info('Running Cloud Security Command Center notification '
                    'module.')

        # At this point, cscc notifier is already determined to be enabled.
        if mode is None or mode == 'bucket':
            self._send_findings_to_gcs(violations, gcs_path)
        elif mode == 'api':
            self._send_findings_to_cscc(violations, organization_id)
        else:
            LOGGER.info(
                'A valid mode for CSCC notification was not selected: %s. '
                'Please use either "bucket" or "api" mode.', mode)
