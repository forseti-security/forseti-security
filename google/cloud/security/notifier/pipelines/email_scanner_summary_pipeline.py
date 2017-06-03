# Copyright 2017 Google Inc.
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
"""Email pipeline to notify that inventory snapshots have been completed."""

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long,no-name-in-module
import collections

from google.cloud.security.common.util import errors as util_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long,no-name-in-module


LOGGER = log_util.get_logger(__name__)


class EmailScannerSummaryPipeline(bnp.BaseNotificationPipeline):
    """Email pipeline for inventory snapshot summary."""

    # TODO: See if the base pipline init() can be reused.
    def __init__(self, sendgrid_key):  # pylint: disable=super-init-not-called
        self.email_util = EmailUtil(sendgrid_key)

    def _compose(  # pylint: disable=arguments-differ
            self, all_violations, total_resources):
        """Compose the scan summary.
        Build a summary of the violations and counts for the email.
        resource summary:
            {
                RESOURCE_TYPE: {
                    'pluralized_resource_type': '{RESOURCE_TYPE}s'
                    'total': TOTAL,
                    'violations': {
                        RESOURCE_ID: NUM_VIOLATIONS,
                        RESOURCE_ID: NUM_VIOLATIONS,
                        ...
                    }
                },
                ...
            }
        Args:
            all_violations: List of violations.
            total_resources: A dict of the resources and their count.

        Returns:
            total_violations: Integer of the total violations.
            resource_summaries: Dictionary of resource to violations.
                {'organization':
                    {'pluralized_resource_type': 'Organizations',
                     'total': 1,
                     'violations': OrderedDict([('660570133860', 67)])},
                 'project':
                    {'pluralized_resource_type': 'Projects',
                     'total': 41,
                     'violations': OrderedDict([('foo1_project', 111),
                                                ('foo2_project', 222),
                                                ('foo3_project', 333)])}}
        """

        resource_summaries = {}
        total_violations = 0

        for violation in sorted(all_violations, key=lambda v: v.resource_id):
            resource_type = violation.resource_type
            if resource_type not in resource_summaries:
                resource_summaries[resource_type] = {
                    'pluralized_resource_type': resource_util.pluralize(
                        resource_type),
                    'total': total_resources[resource_type],
                    'violations': collections.OrderedDict()
                }

            # Keep track of # of violations per resource id.
            if (violation.resource_id not in
                    resource_summaries[resource_type]['violations']):
                resource_summaries[resource_type][
                    'violations'][violation.resource_id] = 0

            resource_summaries[resource_type][
                'violations'][violation.resource_id] += len(violation.members)
            total_violations += len(violation.members)

        return total_violations, resource_summaries

    def _send(  # pylint: disable=arguments-differ
            self, csv_name, output_filename, now_utc, violation_errors,
            total_violations, resource_summaries, email_sender,
            email_recipient):
        """Send a summary email of the scan.

        Args:
            csv_name: The full path of the local csv filename.
            output_filename: String of the output filename.
            now_utc: The UTC datetime right now.
            violation_errors: Iterable of violation errors.
            total_violations: Integer of the total violations.
            resource_summaries: Dictionary of resource to violations.
                {'organization':
                    {'pluralized_resource_type': 'Organizations',
                     'total': 1,
                     'violations': OrderedDict([('660570133860', 67)])},
                 'project':
                    {'pluralized_resource_type': 'Projects',
                     'total': 41,
                     'violations': OrderedDict([('foo1_project', 111),
                                                ('foo2_project', 222),
                                                ('foo3_project', 333)])}}
            email_sender: String of the sender of the email.
            email_recipient: String of the recipient of the email.
        """

        # Render the email template with values.
        scan_date = now_utc.strftime('%Y %b %d, %H:%M:%S (UTC)')
        email_content = EmailUtil.render_from_template(
            'scanner_summary.jinja', {
                'scan_date':  scan_date,
                'resource_summaries': resource_summaries,
                'violation_errors': violation_errors,
            })

        # Create an attachment out of the csv file and base64 encode the
        # content.
        attachment = EmailUtil.create_attachment(
            file_location=csv_name,
            content_type='text/csv',
            filename=output_filename,
            disposition='attachment',
            content_id='Scanner Violations'
        )
        scanner_subject = 'Policy Scan Complete - {} violation(s) found'.format(
            total_violations)
        self.email_util.send(
            email_sender=email_sender,
            email_recipient=email_recipient,
            email_subject=scanner_subject,
            email_content=email_content,
            content_type='text/html',
            attachment=attachment)

    def run(  # pylint: disable=arguments-differ
            self, csv_name, output_filename, now_utc, all_violations,
            total_resources, violation_errors, email_sender, email_recipient):
        """Run the email pipeline

        Args:
            csv_name: The full path of the local csv filename.
            output_filename: String of the output filename.
            now_utc: The UTC datetime right now.
            all_violations: The list of violations.
            total_resources: A dict of the resources and their count.
            violation_errors: Iterable of violation errors.
            email_sender: String of the sender of the email.
            email_recipient: String of the recipient of the email.

        Returns:
             None
        """
        total_violations, resource_summaries = self._compose(
            all_violations, total_resources)

        self._send(csv_name, output_filename, now_utc, violation_errors,
                   total_violations, resource_summaries, email_sender,
                   email_recipient)
