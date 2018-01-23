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

"""Email pipeline to perform notifications"""

from datetime import datetime
import tempfile

# TODO: Investigate improving so we can avoid the pylint disable.
# pylint: disable=line-too-long
from google.cloud.security.common.util import errors as util_errors
from google.cloud.security.common.util import log_util
from google.cloud.security.common.util import parser
from google.cloud.security.common.util.email_util import EmailUtil
from google.cloud.security.notifier.pipelines import base_notification_pipeline as bnp
# pylint: enable=line-too-long


LOGGER = log_util.get_logger(__name__)

VIOLATIONS_JSON_FMT = 'violations.{}.{}.{}.json'
OUTPUT_TIMESTAMP_FMT = '%Y%m%dT%H%M%SZ'


class EmailViolationsPipeline(bnp.BaseNotificationPipeline):
    """Email pipeline to perform notifications"""

    def __init__(self, resource, cycle_timestamp,
                 violations, global_configs, notifier_config, pipeline_config):
        """Initialization.

        Args:
            resource (str): Violation resource name.
            cycle_timestamp (str): Snapshot timestamp,
               formatted as YYYYMMDDTHHMMSSZ.
            violations (dict): Violations.
            global_configs (dict): Global configurations.
            notifier_config (dict): Notifier configurations.
            pipeline_config (dict): Pipeline configurations.
        """
        super(EmailViolationsPipeline, self).__init__(resource,
                                                      cycle_timestamp,
                                                      violations,
                                                      global_configs,
                                                      notifier_config,
                                                      pipeline_config)
        self.mail_util = EmailUtil(self.pipeline_config['sendgrid_api_key'])

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

    def _make_attachment(self):
        """Create the attachment object.

        Returns:
            attachment: SendGrid attachment object or `None` in case of
            failure.
        """
        attachment = None
        with tempfile.NamedTemporaryFile() as tmp_file:
            tmp_file.write(parser.json_stringify(self.violations))
            tmp_file.flush()
            attachment = self.mail_util.create_attachment(
                file_location=tmp_file.name,
                content_type='text/json',
                filename=self._get_output_filename(),
                disposition='attachment',
                content_id='Violations'
            )
        return attachment

    def _make_content(self):
        """Create the email content.

        Returns:
            str: Email subject.
            unicode: Email template content rendered with
                the provided variables.
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

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            dict: A map of the email with subject, content, attachemnt
        """
        del kwargs

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
            **kwargs: Arbitrary keyword arguments.
                subject: Email subject
                conetent: Email content
                attachment: Attachment object
        """
        notification_map = kwargs.get('notification')
        subject = notification_map['subject']
        content = notification_map['content']
        attachment = notification_map['attachment']

        try:
            self.mail_util.send(
                email_sender=self.pipeline_config['sender'],
                email_recipient=self.pipeline_config['recipient'],
                email_subject=subject,
                email_content=content,
                content_type='text/html',
                attachment=attachment)
        except util_errors.EmailSendError:
            LOGGER.warn('Unable to send Violations email')

    def run(self):
        """Run the email pipeline"""
        email_notification = self._compose()
        self._send(notification=email_notification)
