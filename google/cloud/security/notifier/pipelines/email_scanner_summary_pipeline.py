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
"""Email pipeline for scanner summary."""

import collections

# pylint: disable=line-too-long
from google.cloud.security.common.util import errors as util_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.common.gcp_type import resource_util
from google.cloud.security.notifier.pipelines import base_email_notification_pipeline as bnp
# pylint: enable=line-too-long

LOGGER = log_util.get_logger(__name__)


class EmailScannerSummaryPipeline(bnp.BaseEmailNotificationPipeline):
    """Email pipeline for scanner summary."""

    # TODO: See if the base pipline init() can be reused.
    def __init__(self, sendgrid_key):  # pylint: disable=super-init-not-called
        """Initialize.

        Args:
            sendgrid_key (str): The SendGrid API key.
        """
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
                        RESOURCE_ID: {
                            new: NEW_NUM_VIOLATIONS,
                            total: TOTAL_NUM_VIOLATIONS
                        },
                        RESOURCE_ID: {
                            new: NEW_NUM_VIOLATIONS,
                            total: TOTAL_NUM_VIOLATIONS
                        },
                        ...
                    }
                },
                ...
            }
        Args:
            all_violations (list): List of violations.
            total_resources (dict): A dict of the resources and their count.

        Returns:
            int: total_violations, an integer of the total violations.
            int: total_new_violations, an integer of the total new violations.
            dict: resource_summaries, a dict of resource to violations.
                {'organization':
                    {'pluralized_resource_type': 'Organizations',
                     'total': 1,
                     'violations': OrderedDict([('660570133860', {new: 11, total: 11})])},
                 'project':
                    {'pluralized_resource_type': 'Projects',
                     'total': 41,
                     'violations': OrderedDict([('foo1_project', {new: 11, total: 11}),
                                                ('foo2_project', {new: 11, total: 11}),
                                                ('foo3_project', {new: 11, total: 11})])}}
        """
        resource_summaries = {}
        total_violations = 0
        total_new_violations = 0

        for violation in sorted(all_violations,
                                key=lambda v: v.get('resource_id')):
            resource_id = violation.get('resource_id')
            resource_type = violation.get('resource_type')
            if resource_type not in resource_summaries:
                resource_summaries[resource_type] = {
                    'pluralized_resource_type': resource_util.pluralize(
                        resource_type),
                    'total': total_resources[resource_type],
                    'violations': collections.OrderedDict()
                }

            # Keep track of # of violations per resource id.
            if (resource_id not in
                    resource_summaries[resource_type]['violations']):
                resource_summaries[resource_type]['violations'][resource_id] = {
                    'total': 0,
                    'new': 0
                    }

            resource_summaries[resource_type]['violations'][resource_id]['total'] += 1

            # Keep track of # of new violations per resource id.
            if violation.get('new_violation'):
                resource_summaries[resource_type]['violations'][resource_id]['new'] += 1
                total_new_violations += 1

            total_violations += 1

        return total_violations, total_new_violations, resource_summaries

    def _send(  # pylint: disable=arguments-differ
            self, csv_name, output_filename, now_utc, violation_errors,
            total_violations, total_new_violations, resource_summaries, email_sender,
            email_recipient, email_description):
        """Send a summary email of the scan.

        Args:
            csv_name (str): The full path of the local csv filename.
            output_filename (str): The output filename.
            now_utc (datetime): The UTC datetime right now.
            violation_errors (iterable): Iterable of violation errors.
            total_violations (int): The total violations.
            total_new_violations (int): The total new violations.
            resource_summaries (dict): Maps resource to violations.
                {'organization':
                    {'pluralized_resource_type': 'Organizations',
                     'total': 1,
                     'new_violations': OrderedDict([('660570133860', 6)]),
                     'violations': OrderedDict([('660570133860', 67)])},
                 'project':
                    {'pluralized_resource_type': 'Projects',
                     'total': 41,
                     'new_violations': OrderedDict([('foo1_project', 1),
                                                ('foo2_project', 2),
                                                ('foo3_project', 3)]),
                     'violations': OrderedDict([('foo1_project', 111),
                                                ('foo2_project', 222),
                                                ('foo3_project', 333)])}}
            email_sender (str): The sender of the email.
            email_recipient (str): The recipient of the email.
            email_description (str): Brief scan description to include in the
                subject of the email, e.g. 'Policy Scan'.
        """
        # Render the email template with values.
        attachment = None
        scan_date = now_utc.strftime('%Y %b %d, %H:%M:%S (UTC)')
        email_content = EmailUtil.render_from_template(
            'scanner_summary.jinja', {
                'total_violations': total_violations,
                'total_new_violations': total_new_violations,
                'scan_date':  scan_date,
                'resource_summaries': resource_summaries,
                'violation_errors': violation_errors,
            })

        # Create an attachment out of the csv file and base64 encode the
        # content.
        if total_violations:
            attachment = EmailUtil.create_attachment(
                file_location=csv_name,
                content_type='text/csv',
                filename=output_filename,
                disposition='attachment',
                content_id='Scanner Violations'
            )
        scanner_subject = '{} Complete - {} violation(s) found'.format(
            email_description, total_violations)
        try:
            self.email_util.send(
                email_sender=email_sender,
                email_recipient=email_recipient,
                email_subject=scanner_subject,
                email_content=email_content,
                content_type='text/html',
                attachment=attachment)
        except util_errors.EmailSendError:
            LOGGER.warn('Unable to send Scanner Summary email')

    def run(  # pylint: disable=arguments-differ
            self, csv_name, output_filename, now_utc, all_violations,
            total_resources, violation_errors, email_sender, email_recipient,
            email_description):
        """Run the email pipeline

        Args:
            csv_name (str): The full path of the local csv filename.
            output_filename (str): String of the output filename.
            now_utc (datetime): The UTC datetime right now.
            all_violations (list): The list of violations.
            total_resources (dict): A dict of the resources and their count.
            violation_errors (iterable): Iterable of violation errors.
            email_sender (str): The sender of the email.
            email_recipient (str): The recipient of the email.
            email_description (str): Brief scan description to include in the
                subject of the email, e.g. 'Policy Scan'.
        """

        total_violations, total_new_violations, resource_summaries = self._compose(
            all_violations, total_resources)

        self._send(csv_name, output_filename, now_utc, violation_errors,
                   total_violations, total_new_violations, resource_summaries, email_sender,
                   email_recipient, email_description)
