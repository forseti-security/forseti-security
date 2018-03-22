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

"""Email notifier to perform notifications"""

from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.util import email
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.notifier.notifiers import base_notification

LOGGER = logger.get_logger(__name__)

TEMP_DIR = '/tmp'


class EmailViolations(base_notification.BaseNotification):
    """Email notifier to perform notifications"""

    def __init__(self, resource, cycle_timestamp,
                 violations, global_configs, notifier_config,
                 notification_config):
        """Initialization.

        Args:
            resource (str): Violation resource name.
            cycle_timestamp (str): Snapshot timestamp.
            violations (dict): Violations.
            global_configs (dict): Global configurations.
            notifier_config (dict): Notifier configurations.
            notification_config (dict): notifier configurations.
        """
        super(EmailViolations, self).__init__(resource,
                                              cycle_timestamp,
                                              violations,
                                              global_configs,
                                              notifier_config,
                                              notification_config)
        self.mail_util = email.EmailUtil(
            self.notification_config['sendgrid_api_key'])

    def _get_output_filename(self):
        """Create the output filename.

        Returns:
            str: The output filename for the violations json.
        """
        now_utc = date_time.get_utc_now_datetime()
        output_timestamp = now_utc.strftime(
            string_formats.TIMESTAMP_TIMEZONE_FILES)
        output_filename = string_formats.VIOLATION_CSV_FMT.format(
            self.resource,
            self.cycle_timestamp,
            output_timestamp)
        return output_filename

    def _make_attachment(self):
        """Create the attachment object.

        Returns:
            attachment: SendGrid attachment object.
        """
        output_file_name = self._get_output_filename()
        with csv_writer.write_csv(resource_name='violations',
                                  data=self.violations,
                                  write_header=True) as csv_file:
            output_csv_name = csv_file.name
            LOGGER.info('CSV filename: %s', output_csv_name)
            attachment = self.mail_util.create_attachment(
                file_location=csv_file.name,
                content_type='text/csv', filename=output_file_name,
                content_id='Violations')

        return attachment

    def _make_content(self):
        """Create the email content.

        Returns:
            str: Email subject.
            unicode: Email template content rendered with
                the provided variables.
        """
        timestamp = date_time.get_datetime_from_string(
            self.cycle_timestamp, string_formats.TIMESTAMP_MICROS)
        pretty_timestamp = timestamp.strftime(string_formats.TIMESTAMP_READABLE)
        email_content = self.mail_util.render_from_template(
            'notification_summary.jinja', {
                'scan_date': pretty_timestamp,
                'resource': self.resource,
                'violation_errors': self.violations,
            })

        email_subject = 'Forseti Violations {} - {}'.format(
            pretty_timestamp, self.resource)
        return email_subject, email_content

    def _compose(self, **kwargs):
        """Compose the email notifier map

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
                email_sender=self.notification_config['sender'],
                email_recipient=self.notification_config['recipient'],
                email_subject=subject,
                email_content=content,
                content_type='text/html',
                attachment=attachment)
        except util_errors.EmailSendError:
            LOGGER.warn('Unable to send Violations email')

    def run(self):
        """Run the email notifier"""
        email_notification = self._compose()
        self._send(notification=email_notification)
