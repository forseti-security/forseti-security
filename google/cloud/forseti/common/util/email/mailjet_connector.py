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

"""Mailjet email connector module."""

# The pre-commit linter will complain about useless disable of no-member, but
# this is needed because quiet the Sendgrid no-member error on Travis.
# pylint: disable=no-member,useless-suppression

from base64 import b64encode
import urllib.request
import urllib.error
import urllib.parse
from future import standard_library
from requests import Response
from retrying import retry
from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import retryable_exceptions
from google.cloud.forseti.common.util.email import base_email_connector

standard_library.install_aliases()

LOGGER = logger.get_logger(__name__)

try:
    from mailjet_rest import Client
    MAILJET_ENABLED = True
except ImportError:
    LOGGER.warning('Cannot enable Mailjet connector because the '
                   '`mailjet_rest` library was not found. Run '
                   '`sudo pip3 install mailjet_rest` to install '
                   'Mailjet.')
    MAILJET_ENABLED = False


class Attachment:
    """Mailjet attachment."""
    def __init__(self,
                 filename,
                 content_type,
                 content,
                 disposition='attachment'):
        """Create a Mailjet attachment.

        Mailjet attachments file content must be base64 encoded.

        Args:
            content_type (str): The content type of the attachment.
            content (str): The base64 encoded content the attachment.
            filename (str): The filename of attachment.
            disposition (str): Content disposition, defaults to "attachment".
        """
        self.filename = filename
        self.content_type = content_type
        self.content = content
        self.disposition = disposition

    def payload(self):
        """Returns mailjet_rest API attachment payload.

        Returns:
            dict: mailjet_rest API attachment payload
        """
        return {
            'Filename': self.filename,
            'Content-type': self.content_type,
            'content': self.content
        }


class MailjetConnector(base_email_connector.BaseEmailConnector):
    """Utility for sending emails using Mailjet API Key."""

    def __init__(self, sender, recipient, auth, custom=None):
        """Initialize the email util.

        Args:
            sender (str): The email sender.
            recipient (str): The email recipient.
            auth (dict): A set of authentication attributes
            corresponding to the selected connector.
            custom (dict): A set of custom attributes,
            only 'campaign' attribute is used yet
        """
        self.sender = sender
        self.recipient = recipient
        self.mailjet = Client(
            auth=(
                auth.get('api_key'),
                auth.get('api_secret')
            )
        )
        self.campaign = custom.get('campaign') if custom else None

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def _execute_send(self, email) -> Response:
        """Executes the sending of the email.

        This needs to be a standalone method so that we can wrap it with retry,
        and the final exception can be gracefully handled upstream.

        Args:
            email (dict): Mailjet mail object

        Returns:
            dict: urllib2 response object
        """
        return self.mailjet.send.create(data=email)

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
            email_content (str): The email HTML content (aka, body).
            content_type (str): The email content type.
            attachment (Attachment): A Mailjet Attachment.

        Raises:
            EmailSendError: An error with sending email has occurred.
        """
        if not email_sender or not email_recipient:
            LOGGER.warning('Unable to send email: sender=%s, recipient=%s',
                           email_sender, email_recipient)
            raise util_errors.EmailSendError

        email = {
            'FromEmail': email_sender,
            'FromName': email_sender,
            'Subject': email_subject,
            'Html-part': email_content,
            'Recipients': [
                {'Email': email_address}
                for email_address in email_recipient.split(',')
            ],
            'Attachments': [attachment] if attachment else []
        }

        if attachment:
            if attachment.disposition == 'attachment':
                email['Attachments'] = [attachment.payload()]
            elif attachment.disposition == 'inline':
                email['Inline_attachments'] = [attachment.payload()]
            else:
                LOGGER.exception(
                    'Unable to send attachment, disposition is invalid: %s',
                    attachment.disposition
                )
                raise util_errors.EmailSendError

        if self.campaign:
            email['Mj-campaign'] = self.campaign

        try:
            response = self._execute_send(email)
        except urllib.error.HTTPError as e:
            LOGGER.exception('Unable to send email: %s %s', e.code, e.reason)
            raise util_errors.EmailSendError

        if 200 <= response.status_code < 300:
            LOGGER.info('Email accepted for delivery:\n%s', email_subject)
        else:
            LOGGER.error('Unable to send email:\n%s\n%s\n%s\n%s',
                         email_subject, response.status_code,
                         response.content, response.headers)
            raise util_errors.EmailSendError

    @classmethod
    def create_attachment(cls,
                          file_location=None,
                          content_type=None,
                          filename=None,
                          disposition='attachment',
                          content_id=None):
        """Create a Mailjet attachment.

        Mailjet attachments file content must be base64 encoded.

        Args:
            file_location (str): The path of the file.
            content_type (str): The content type of the attachment.
            filename (str): The filename of attachment.
            disposition (str): Content disposition, defaults to "attachment".
            content_id (str): The content id.

        Returns:
            Attachment: A Mailjet Attachment.
        """
        with open(file_location, 'rb') as f:
            return Attachment(
                filename=filename,
                content_type=content_type,
                content=b64encode(f.read()).decode('utf-8'),
                disposition=disposition
            )
