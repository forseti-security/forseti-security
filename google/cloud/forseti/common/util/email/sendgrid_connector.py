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

"""Email utility module."""

# The pre-commit linter will complain about useless disable of no-member, but
# this is needed because quiet the Sendgrid no-member error on Travis.
# pylint: disable=no-member,useless-suppression


import base64
import urllib2

import sendgrid
from sendgrid.helpers import mail
from retrying import retry

from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import retryable_exceptions
from google.cloud.forseti.common.util.email import base_email_connector


LOGGER = logger.get_logger(__name__)


class SendgridConnector(base_email_connector.BaseEmailConnector):
    """Utility for sending emails using Sendgrid API Key."""

    def __init__(self, sender, recipient, kwargs):
        """Initialize the email util.

        Args:
            sender (str): The email sender.
            recipient (str): The email recipient.
            **kwargs (dict): A set of authentication attributes
            corresponding to the selected connector.
        """
        self.sender = sender
        self.recipient = recipient
        if kwargs.get('api_key'):
            api_key = kwargs.get('api_key')
        # else block below is for backward compatibility
        else:
            api_key = kwargs.get('sendgrid_api_key')
        self.sendgrid = sendgrid.SendGridAPIClient(apikey=api_key)

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def _execute_send(self, email):
        """Executes the sending of the email.

        This needs to be a standalone method so that we can wrap it with retry,
        and the final exception can be gracefully handled upstream.

        Args:
            email (SendGrid): SendGrid mail object

        Returns:
            dict: urllib2 response object
        """
        return self.sendgrid.client.mail.send.post(request_body=email.get())

    @staticmethod
    def _add_recipients(email, email_recipients):
        """Add multiple recipients to the sendgrid email object.

        Args:
            email (SendGrid): SendGrid mail object
            email_recipients (Str): comma-separated text of the email recipients

        Returns:
            SendGrid: SendGrid mail object with multiple recipients.
        """
        personalization = mail.Personalization()
        recipients = email_recipients.split(',')
        for recipient in recipients:
            personalization.add_to(mail.Email(recipient))
        email.add_personalization(personalization)
        return email

    def send(self, email_sender=None, email_recipient=None,
             email_subject=None, email_content=None, content_type=None,
             attachment=None):
        """Send an email.

        This uses the SendGrid API.
        https://github.com/sendgrid/sendgrid-python

        The minimum required info to send email are:
        sender, recipient, subject, and content (the body)

        Args:
            email_sender (str): The email sender.
            email_recipient (str): The email recipient.
            email_subject (str): The email subject.
            email_content (str): The email content (aka, body).
            content_type (str): The email content type.
            attachment (Attachment): A SendGrid Attachment.

        Raises:
            EmailSendError: An error with sending email has occurred.
        """
        if not email_sender or not email_recipient:
            LOGGER.warn('Unable to send email: sender=%s, recipient=%s',
                        email_sender, email_recipient)
            raise util_errors.EmailSendError

        email = mail.Mail()
        email.from_email = mail.Email(email_sender)
        email.subject = email_subject
        email.add_content(mail.Content(content_type, email_content))

        email = self._add_recipients(email, email_recipient)

        if attachment:
            email.add_attachment(attachment)

        try:
            response = self._execute_send(email)
        except urllib2.HTTPError as e:
            LOGGER.exception('Unable to send email: %s %s',
                             e.code, e.reason)
            raise util_errors.EmailSendError

        if response.status_code == 202:
            LOGGER.info('Email accepted for delivery:\n%s',
                        email_subject)
        else:
            LOGGER.error('Unable to send email:\n%s\n%s\n%s\n%s',
                         email_subject, response.status_code,
                         response.body, response.headers)
            raise util_errors.EmailSendError

    @classmethod
    def create_attachment(cls, file_location, content_type, filename,
                          disposition='attachment', content_id=None):
        """Create a SendGrid attachment.

        SendGrid attachments file content must be base64 encoded.

        Args:
            file_location (str): The path of the file.
            content_type (str): The content type of the attachment.
            filename (str): The filename of attachment.
            disposition (str): Content disposition, defaults to "attachment".
            content_id (str): The content id.

        Returns:
            Attachment: A SendGrid Attachment.
        """
        file_content = ''
        with open(file_location, 'rb') as f:
            file_content = f.read()
        content = base64.b64encode(file_content)

        attachment = mail.Attachment()
        attachment.content = content
        attachment.type = content_type
        attachment.filename = filename
        attachment.disposition = disposition
        attachment.content_id = content_id

        return attachment
