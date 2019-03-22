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
import ast
import json
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

    def _transform_for_api(self, violations, source_id=None):
        """Transform forseti violations to findings for CSCC API.

        Args:
            violations (dict): Violations to be sent to CSCC as findings.
            source_id (str): Unique ID assigned by CSCC, to the organization
                that the violations are originating from.

        Returns:
            list: violations in findings format; each violation is a dict.
        """
        findings = []

        # beta api
        LOGGER.debug('Transforming findings with beta API. source_id: %s',
                     source_id)
        for violation in violations:
            # CSCC can't accept the full hash, so this must be shortened.
            finding_id = violation.get('violation_hash')[:32]
            finding = {
                'name': '{0}/findings/{1}'.format(
                    source_id, violation.get('violation_hash')[:32]),
                'parent': source_id,
                'resource_name': violation.get('full_name'),
                'state': 'ACTIVE',
                'category': violation.get('violation_type'),
                'event_time': violation.get('created_at_datetime'),
                'source_properties': {
                    'source': 'FORSETI',
                    'db_source': 'table:{}/id:{}'.format(
                        'violations', violation.get('id')),
                    'inventory_index_id': self.inv_index_id,
                    'resource_data': (
                        json.dumps(violation.get('resource_data'),
                                   sort_keys=True)),
                    'resource_id': violation.get('resource_id'),
                    'resource_type': violation.get('resource_type'),
                    'rule_index': violation.get('rule_index'),
                    'rule_name': violation.get('rule_name'),
                    'scanner_index_id': violation.get('scanner_index_id'),
                    'violation_data': (
                        json.dumps(violation.get('violation_data'),
                                   sort_keys=True))
                },
            }
            findings.append([finding_id, finding])
        return findings

    @staticmethod
    def find_inactive_findings(new_findings, findings_in_cscc):
        """Finds the findings that does not correspond to the latest scanner run
           and updates it's state to inactive.

        Args:
            new_findings (list): Latest violations that are transformed to
                findings.
            findings_in_cscc (list): Findings pulled from CSCC that
                corresponds to the previous scanner run.

        Returns:
            list: Findings whose state has been marked as 'INACTIVE'.
        """

        inactive_findings = []
        new_findings_map = {}

        for finding_list in new_findings:
            finding_id = finding_list[0]
            finding = finding_list[1]
            add_to_dict = {finding_id: finding}
            new_findings_map.update(add_to_dict)

        for finding_list in findings_in_cscc:
            finding_id = finding_list[0]
            to_be_updated_finding = finding_list[1]

            if finding_id not in new_findings_map:
                to_be_updated_finding['state'] = 'INACTIVE'
                current_time = date_time.get_utc_now_datetime()
                actual_time = current_time.strftime(
                    string_formats.TIMESTAMP_TIMEZONE)
                to_be_updated_finding['event_time'] = actual_time
                inactive_findings.append([finding_id, to_be_updated_finding])
        return inactive_findings

    # pylint: disable=too-many-locals
    def _send_findings_to_cscc(self, violations, source_id=None):
        """Send violations to CSCC directly via the CSCC API.

        Args:
            violations (dict): Violations to be uploaded as findings.
            source_id (str): Unique ID assigned by CSCC, to the organization
                that the violations are originating from.
        """

        # beta api
        formatted_cscc_findings = []
        LOGGER.debug('Sending findings to CSCC with beta API. source_id: '
                     '%s', source_id)
        new_findings = self._transform_for_api(violations,
                                               source_id=source_id)

        client = securitycenter.SecurityCenterClient(version='v1beta1')

        paged_findings_in_cscc = client.list_findings(source_id=source_id)

        # No need to use the next page token, as the results here will
        # return all the pages.
        for page in paged_findings_in_cscc:
            formated_findings_in_page = (
                ast.literal_eval(json.dumps(page)))
            findings_in_page = formated_findings_in_page.get('findings')
            for finding_data in findings_in_page:
                name = finding_data.get('name')
                finding_id = name[-32:]
                formatted_cscc_findings.append([finding_id, finding_data])

        inactive_findings = self.find_inactive_findings(
            new_findings,
            formatted_cscc_findings)

        for finding_list in new_findings:
            finding_id = finding_list[0]
            finding = finding_list[1]
            LOGGER.debug('Creating finding CSCC:\n%s.', finding)
            try:
                client.create_finding(finding, source_id=source_id,
                                      finding_id=finding_id)
                LOGGER.debug('Successfully created finding in CSCC:\n%s',
                             finding)
            except api_errors.ApiExecutionError:
                LOGGER.exception('Encountered CSCC API error.')
                continue

        for finding_list in inactive_findings:
            finding_id = finding_list[0]
            finding = finding_list[1]
            LOGGER.debug('Updating finding CSCC:\n%s.', finding)
            try:
                client.update_finding(finding,
                                      finding_id,
                                      source_id=source_id)
                LOGGER.debug('Successfully updated finding in CSCC:\n%s',
                             finding)
            except api_errors.ApiExecutionError:
                LOGGER.exception('Encountered CSCC API error.')
                continue

        return

    def run(self, violations, source_id=None):
        """Generate the temporary json file and upload to GCS.

        Args:
            violations (dict): Violations to be uploaded as findings.
            source_id (str): Unique ID assigned by CSCC, to the organization
                that the violations are originating from.
        """
        LOGGER.info('Running Cloud Security Command Center notification '
                    'module.')

        # At this point, cscc notifier is already determined to be enabled.

        # beta api
        LOGGER.debug('Running CSCC with beta API. source_id: %s', source_id)
        self._send_findings_to_cscc(violations, source_id=source_id)
        return
