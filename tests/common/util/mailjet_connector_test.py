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

"""Tests for the Mailjet email connector module."""
import tempfile
import unittest
from base64 import b64decode
from unittest.mock import patch, call
from urllib.error import HTTPError

from google.cloud.forseti.common.util.email import mailjet_connector
from google.cloud.forseti.common.util.email.mailjet_connector import MailjetConnector, Attachment
from google.cloud.forseti.common.util.errors import EmailSendError
from tests.unittest_utils import ForsetiTestCase


class MailjetConnectorTest(ForsetiTestCase):
    """Tests for the Mailjet email connector module."""

    def setUp(self):
        if not mailjet_connector.MAILJET_ENABLED:
            self.skipTest('Package `mailjet` not installed.')

        self.connector = MailjetConnector(
            sender="this field is useless",
            recipient="this field is also useless",
            auth={},
            custom={'campaign': self.campaign}
        )

    @classmethod
    def setUpClass(cls):
        cls.filename = 'test_attachment.csv'
        cls.content_type = 'text/csv'

        cls.attachment_content = 'attachment readable content\n'
        cls.attachment_content_b64 = 'YXR0YWNobWVudCByZWFkYWJsZSBjb250ZW50Cg=='

        cls.attachment = Attachment(
            filename=cls.filename,
            content_type=cls.content_type,
            content=cls.attachment_content_b64
        )

        cls.campaign = 'forseti'

    def test_create_attachment(self):
        """Test create attachment."""
        with tempfile.NamedTemporaryFile() as tmp_file:
            with open(tmp_file.name, "w") as f:
                f.write(self.attachment_content)

            attachment = MailjetConnector.create_attachment(
                file_location=tmp_file.name,
                content_type=self.content_type,
                filename=self.filename
            )

            self.assertEqual(self.attachment.payload(), attachment.payload())

            with open(tmp_file.name, "r") as f:
                self.assertEqual(
                    b64decode(attachment.content).decode('UTF-8'),
                    f.read()
                )

    def test_send_ok(self):
        email_sender = "sender@company.com"
        email_recipient = "recipient@company.com"
        email_subject = "subject"
        email_content = "content"
        email_content_type = "content-type"

        with patch.object(self.connector, "_execute_send") as execute_send_mock:
            execute_send_mock.return_value.status_code = 202

            self.connector.send(
                email_sender=email_sender,
                email_recipient=email_recipient,
                email_subject=email_subject,
                email_content=email_content,
                content_type=email_content_type,
                attachment=self.attachment
            )

            self.assertEqual(execute_send_mock.call_count, 1)
            execute_send_mock.assert_has_calls([
                call({
                    'FromEmail': email_sender,
                    'FromName': email_sender,
                    'Subject': email_subject,
                    'Html-part': email_content,
                    'Recipients': [{'Email': email_recipient}],
                    'Attachments': [self.attachment.payload()],
                    'Mj-campaign': self.campaign
                })
            ])

    def test_send_ko_unexpected_code(self):
        email_sender = "sender@company.com"
        email_recipient = "recipient@company.com"
        email_subject = "subject"
        email_content = "content"
        email_content_type = "content-type"

        with patch.object(self.connector, "_execute_send") as execute_send_mock:
            execute_send_mock.return_value.status_code = 500

            with self.assertRaises(EmailSendError):
                self.connector.send(
                    email_sender=email_sender,
                    email_recipient=email_recipient,
                    email_subject=email_subject,
                    email_content=email_content,
                    content_type=email_content_type,
                    attachment=self.attachment
                )

            self.assertEqual(execute_send_mock.call_count, 1)

    def test_send_ko_http_error(self):
        email_sender = "sender@company.com"
        email_recipient = "recipient@company.com"
        email_subject = "subject"
        email_content = "content"
        email_content_type = "content-type"

        http_error = HTTPError(url="url", code=500, msg="message", hdrs={}, fp=None)

        with patch.object(self.connector, "_execute_send", side_effect=http_error) as execute_send_mock:
            with self.assertRaises(EmailSendError):
                self.connector.send(
                    email_sender=email_sender,
                    email_recipient=email_recipient,
                    email_subject=email_subject,
                    email_content=email_content,
                    content_type=email_content_type,
                    attachment=self.attachment
                )

            self.assertEqual(execute_send_mock.call_count, 1)

    def test_send_ko_no_sender(self):
        email_recipient = "recipient@company.com"
        email_subject = "subject"
        email_content = "content"
        email_content_type = "content-type"

        with patch.object(self.connector, "_execute_send") as execute_send_mock:
            with self.assertRaises(EmailSendError):
                self.connector.send(
                    email_recipient=email_recipient,
                    email_subject=email_subject,
                    email_content=email_content,
                    content_type=email_content_type,
                    attachment=self.attachment
                )

            self.assertEqual(execute_send_mock.call_count, 0)

    def test_send_ko_no_recipient(self):
        email_sender = "sender@company.com"
        email_subject = "subject"
        email_content = "content"
        email_content_type = "content-type"

        with patch.object(self.connector, "_execute_send") as execute_send_mock:
            with self.assertRaises(EmailSendError):
                self.connector.send(
                    email_sender=email_sender,
                    email_subject=email_subject,
                    email_content=email_content,
                    content_type=email_content_type,
                    attachment=self.attachment
                )

            self.assertEqual(execute_send_mock.call_count, 0)


if __name__ == '__main__':
    unittest.main()
