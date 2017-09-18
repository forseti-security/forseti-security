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

"""Tests the Email utility."""
import unittest

from sendgrid.helpers import mail

from tests.unittest_utils import ForsetiTestCase
from google.cloud.security.common.util import email_util


class EmailUtilTest(ForsetiTestCase):
    """Test the Email utility."""

    def test_can_send_email_to_single_recipient(self):
        """Test if loggers instantiated before set_logger_level will be affected."""

        email = mail.Mail()
        email_recipient='foo@company.com'
        util = email_util.EmailUtil('fake_sendgrid_key')
        email = util._add_recipients(email, email_recipient)

        self.assertEquals(1, len(email.personalizations))

        added_recipients = email.personalizations[0].tos
        self.assertEquals(1, len(added_recipients))
        self.assertEquals('foo@company.com', added_recipients[0].get('email'))


    def test_can_send_email_to_multiple_recipients(self):
        """Test if loggers instantiated before set_logger_level will be affected."""

        email = mail.Mail()
        email_recipient='foo@company.com,bar@company.com'
        util = email_util.EmailUtil('fake_sendgrid_key')
        email = util._add_recipients(email, email_recipient)

        self.assertEquals(1, len(email.personalizations))

        added_recipients = email.personalizations[0].tos
        self.assertEquals(2, len(added_recipients))
        self.assertEquals('foo@company.com', added_recipients[0].get('email'))
        self.assertEquals('bar@company.com', added_recipients[1].get('email'))


if __name__ == '__main__':
    unittest.main()
