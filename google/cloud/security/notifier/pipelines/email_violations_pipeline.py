
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

"""Email pipeline to perform notifications"""

from datetime import datetime

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc
# pylint: disable=missing-param-doc,differing-param-doc


LOGGER = log_util.get_logger(__name__)

TEMP_DIR = '/tmp'
VIOLATIONS_JSON_FMT = 'violations.{}.{}.{}.json'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


class EmailViolationsPipeline(bnp.BaseNotificationPipeline):
    """Email pipeline to perform notifications"""

    def __init__(self, resource, cycle_timestamp,
                 violations, notifier_config, pipeline_config):
        super(EmailViolationsPipeline, self).__init__(resource,
                                                      cycle_timestamp,
                                                      violations,
                                                      notifier_config,
                                                      pipeline_config)
        self.mail_util = EmailUtil(self.pipeline_config['sendgrid_api_key'])

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            The output filename for the violations json.
        """
        now_utc = datetime.utcnow()
        output_timestamp = now_utc.strftime(OUTPUT_TIMESTAMP_FMT)
        output_filename = VIOLATIONS_JSON_FMT.format(self.resource,
                                                     self.cycle_timestamp,
                                                     output_timestamp)
        return output_filename

    def _write_temp_attachment(self):
        """Write the attachment to a temp file.

        Returns:
            The output filename for the violations json just written.
        """
        # Make attachment
        output_file_name = self._get_output_filename()
        output_file_path = '{}/{}'.format(TEMP_DIR, output_file_name)
        with open(output_file_path, 'w+') as f:
            f.write(parser.json_stringify(self.violations))
        return output_file_name

    def _make_attachment(self):
        """Create the attachment object.

        Returns:
            The attachment object.
        """
        output_file_name = self._write_temp_attachment()
        attachment = self.mail_util.create_attachment(
            file_location='{}/{}'.format(TEMP_DIR, output_file_name),
            content_type='text/json',
            filename=output_file_name,
            disposition='attachment',
            content_id='Violations'
        )

        return attachment

    def _make_content(self):
        """Create the email content.

        Returns:
            A tuple containing the email subject and the content
        """
        timestamp = datetime.strptime(
            self.cycle_timestamp, '%Y%m%dT%H%M%SZ')
        pretty_timestamp = timestamp.strftime("%d %B %Y - %H:%M:%S")
        email_content = self.mail_util.render_from_template(
            'notification_summary.jinja', {
                'scan_date':  pretty_timestamp,
                'resource': self.resource,
                'violation_errors': self.violations,
            })

        email_subject = 'Forseti Violations {} - {}'.format(
            pretty_timestamp, self.resource)
        return email_subject, email_content

    def _compose(self, **kwargs):
        """Compose the email pipeline map

        Returns:
            Returns a map with subject, content, attachemnt
        """
        email_map = {}

        attachment = self._make_attachment()
        subject, content = self._make_content()
        email_map['subject'] = subject
        email_map['content'] = content
        email_map['attachment'] = attachment
        return email_map

    def _send(self, **kwargs):
        """Send a summary email of the scan.

        Args:
            subject: Email subject
            conetent: Email content
            attachment: Attachment object
        """
        notification_map = kwargs.get('notification')
        subject = notification_map['subject']
        content = notification_map['content']
        attachment = notification_map['attachment']

        self.mail_util.send(email_sender=self.pipeline_config['sender'],
                            email_recipient=self.pipeline_config['recipient'],
                            email_subject=subject,
                            email_content=content,
                            content_type='text/html',
                            attachment=attachment)

    def run(self):
        """Run the email pipeline"""
        email_notification = self._compose()
        self._send(notification=email_notification)
