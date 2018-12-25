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

"""Tests for the Email utility."""

import mock
import unittest

from sendgrid.helpers import mail

from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util.email import sendgrid_connector
from google.cloud.forseti.common.util import errors as util_errors


class SendgridConnectorTest(ForsetiTestCase):
    """Tests for the Email utility."""

    def test_can_send_email_to_single_recipient(self):
        """Test can send email to single recipient."""

        new_email = mail.Mail()
        email_recipient = 'foo@company.com'
        email_sender = 'bar@company.com'
        email_connector_config = {
            'fake_sendgrid_key': 'xyz010'
        }
        email_util = sendgrid_connector.SendgridConnector(
            email_sender,
            email_recipient,
            email_connector_config)
        new_email = email_util._add_recipients(new_email, email_recipient)

        self.assertEquals(1, len(new_email.personalizations))

        added_recipients = new_email.personalizations[0].tos
        self.assertEquals(1, len(added_recipients))
        self.assertEquals('foo@company.com', added_recipients[0].get('email'))

    def test_can_send_email_to_multiple_recipients(self):
        """Test can send email to multiple recipients."""

        new_email = mail.Mail()
        email_recipient = 'foo@company.com,bar@company.com'
        email_sender = 'xyz@company.com'
        email_connector_config = {
            'fake_sendgrid_key': 'xyz010'
        }
        email_util = sendgrid_connector.SendgridConnector(
            email_sender,
            email_recipient,
            email_connector_config)
        new_email = email_util._add_recipients(new_email, email_recipient)

        self.assertEquals(1, len(new_email.personalizations))

        added_recipients = new_email.personalizations[0].tos
        self.assertEquals(2, len(added_recipients))
        self.assertEquals('foo@company.com', added_recipients[0].get('email'))
        self.assertEquals('bar@company.com', added_recipients[1].get('email'))

    @mock.patch('sendgrid.helpers.mail.Mail', autospec=True)
    def test_no_sender_recip_no_email(self, mock_mail):
        """Test that no sender/recipient doesn't send email."""
        email_connector_config = {
            'fake_sendgrid_key': 'xyz010'
        }
        email_util = sendgrid_connector.SendgridConnector(
            'sender',
            'recipient',
            email_connector_config
        )
        with self.assertRaises(util_errors.EmailSendError):
            email_util.send()


if __name__ == '__main__':
    unittest.main()
