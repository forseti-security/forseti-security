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

"""Email utility module."""

from urllib2 import URLError
from urllib2 import HTTPError

from retrying import retry
import sendgrid
from sendgrid.helpers import mail

from google.cloud.security.common.util.errors import EmailSendError
from google.cloud.security.common.util.log_util import LogUtil
from google.cloud.security.common.util import retryable_exceptions


class EmailUtil(object):
    """Utility for sending emails."""
    
    def __init__(self):
        """Initialize the email util."""
        # TODO: Store and read the sendgrid key from GCS.
        self.logger = LogUtil.setup_logging(__name__)
        api_key = 'my_secret_key'
        self.sendgrid = sendgrid.SendGridAPIClient(apikey=api_key)

    @retry(retry_on_exception=retryable_exceptions.is_retryable_exception,
           wait_exponential_multiplier=1000, wait_exponential_max=10000,
           stop_max_attempt_number=5)
    def _execute_send(self, email):
        """Executes the sending of the email.

        This needs to be a standalone method so that we can wrap it with retry,
        and the final exception can be gracefully handled upstream.

        Args:
            email: sendgrid mail object

        Returns:
            urllib2 response object
        """
        return self.sendgrid.client.mail.send.post(request_body=email.get())

    def send(self, email_sender, email_recipient, email_subject, email_content):
        """Send an email.

        This uses SendGrid.
        https://github.com/sendgrid/sendgrid-python

        The minimum required info to send email are:
        sender, recipient, subject, and content (the body)
        
        Args:
            email_sender: String of the email sender.
            email_recipient: String of the email recipient.
            email_subject: String of the email subject.
            email_content: String of the email content (aka, body).
        
        Returns:
            None.
        
        Raises:
            EmailSendError: An error with sending email has occurred.
        """
        email = mail.Mail(
            mail.Email(email_sender),
            email_subject,
            mail.Email(email_recipient),
            mail.Content('text/plain', email_content)
        )

        try:
            response = self._execute_send(email)
        except (URLError, HTTPError) as e:
            self.logger.error('Unable to send email: {0} {1}'
                .format(e.code, e.reason))
            raise EmailSendError

        if response.status_code == 202:
            self.logger.info('Email accepted for delivery:\n{0}'
                .format(email_subject))
        else:
            self.logger.error('Unable to send email:\n{0}\n{1}\n{2}\n{3}'
                .format(email_subject,
                        response.status_code,
                        response.body,
                        response.headers))
            raise EmailSendError
