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

import tempfile

from google.cloud.forseti.common.data_access import csv_writer
from google.cloud.forseti.common.util import date_time
from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import parser
from google.cloud.forseti.common.util import string_formats
from google.cloud.forseti.common.util.email import email_factory
from google.cloud.forseti.common.util.errors import InvalidInputError
from google.cloud.forseti.notifier.notifiers import base_notification


LOGGER = logger.get_logger(__name__)

TEMP_DIR = '/tmp'


class EmailViolations(base_notification.BaseNotification):
    """Email notifier to perform notifications"""

    def __init__(self, resource, inventory_index_id,
                 violations, global_configs, notifier_config,
                 notification_config):
        """Initialization.

        Args:
            resource (str): Violation resource name.
            inventory_index_id (int64): Inventory index id.
            violations (dict): Violations.
            global_configs (dict): Global configurations.
            notifier_config (dict): Notifier configurations.
            notification_config (dict): notifier configurations.

        Raises:
            InvalidInputError: Raised if invalid input is encountered.
        """
        super(EmailViolations, self).__init__(resource,
                                              inventory_index_id,
                                              violations,
                                              global_configs,
                                              notifier_config,
                                              notification_config)
        try:
            if self.notifier_config.get('email_connector'):
                self.connector = email_factory.EmailFactory(
                    self.notifier_config).get_connector()
            # else block below is added for backward compatibility.
            else:
                self.connector = email_factory.EmailFactory(
                    self.notification_config).get_connector()
        except Exception:
            LOGGER.exception('Error occurred to instantiate connector.')
            raise InvalidInputError(self.notifier_config)

    def _make_attachment_csv(self):
        """Create the attachment object in csv format.

        Returns:
            attachment: SendGrid attachment object.
        """
        output_filename = self._get_output_filename(
            string_formats.VIOLATION_CSV_FMT)
        with csv_writer.write_csv(resource_name='violations',
                                  data=self.violations,
                                  write_header=True) as csv_file:
            output_csv_name = csv_file.name
            LOGGER.info('CSV filename: %s', output_csv_name)
            attachment = self.connector.create_attachment(
                file_location=csv_file.name,
                content_type='text/csv', filename=output_filename,
                content_id='Violations')

        return attachment

    def _make_attachment_json(self):
        """Create the attachment object json format.

        Returns:
            attachment: SendGrid attachment object.
        """
        output_filename = self._get_output_filename(
            string_formats.VIOLATION_JSON_FMT)
        with tempfile.NamedTemporaryFile() as tmp_violations:
            tmp_violations.write(parser.json_stringify(self.violations))
            tmp_violations.flush()
            LOGGER.info('JSON filename: %s', tmp_violations.name)
            attachment = self.connector.create_attachment(
                file_location=tmp_violations.name,
                content_type='application/json',
                filename=output_filename,
                content_id='Violations')

        return attachment

    def _make_content(self):
        """Create the email content.

        Returns:
            str: Email subject.
            unicode: Email template content rendered with
                the provided variables.
        """
        timestamp = date_time.get_date_from_microtimestamp(
            self.inventory_index_id)
        pretty_timestamp = timestamp.strftime(string_formats.TIMESTAMP_READABLE)
        email_content = self.connector.render_from_template(
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

        if self.notifier_config.get('email_connector'):
            data_format = (
                self.notifier_config.get('email_connector')
                .get('data_format', 'csv'))
        # else block below is added for backward compatibility.
        else:
            data_format = self.notification_config.get('data_format', 'csv')

        if data_format not in self.supported_data_formats:
            raise base_notification.InvalidDataFormatError(
                'Email notifier', data_format)

        attachment = None
        if data_format == 'csv':
            attachment = self._make_attachment_csv()
        else:
            attachment = self._make_attachment_json()
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

        if self.notifier_config.get('email_connector'):
            sender = (
                self.notifier_config.get('email_connector').get('sender'))
            recipient = (
                self.notifier_config.get('email_connector').get('recipient'))
        # else block below is added for backward compatibility.
        else:
            sender = self.notification_config['sender']
            recipient = self.notification_config['recipient']
        try:
            self.connector.send(email_sender=sender,
                                email_recipient=recipient,
                                email_subject=subject,
                                email_content=content,
                                content_type='text/html',
                                attachment=attachment)
        except util_errors.EmailSendError:
            LOGGER.warn('Unable to send Violations email')

    def run(self):
        """Run the email notifier"""
        email_notification = self._compose()
        if email_notification:
            self._send(notification=email_notification)
