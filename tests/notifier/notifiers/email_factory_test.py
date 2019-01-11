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

"""Tests for Email Factory"""

from google.cloud.forseti.common.util.email import email_factory
from google.cloud.forseti.common.util.email import sendgrid_connector
from google.cloud.forseti.common.util.errors import InvalidInputError
from tests.unittest_utils import ForsetiTestCase


class EmailFactoryTest(ForsetiTestCase):
    """Tests for Email Factory"""

    def test_get_connector_correctness(self):
        """Test get_connector() correctness."""
        sample_notifier_config = {
            'email_connector_config': {
                'name': 'sendgrid',
                'sender': 'abc',
                'recipient': 'xyz',
                'data_format': 'csv',
                'auth': {
                    'api_key': 'a0b0c0'
                }
            }
        }
        connector = email_factory.EmailFactory(
            sample_notifier_config).get_connector()
        self.assertTrue(isinstance(connector,
                                   sendgrid_connector.SendgridConnector))

    def test_get_connector_invalid_input(self):
        """Test get_connector() with invalid input."""
        incomplete_notifier_config = {
            'email_connector': {
                'sender': 'abc',
                'recipient': 'xyz',
                'data_format': 'csv',
                'auth': {
                    'api_key': 'a0b0c0'
                }
            }
        }
        self.assertRaises(InvalidInputError,
                          email_factory.EmailFactory(
                              incomplete_notifier_config).get_connector)

    def test_get_connector_empty(self):
        """Test get_connector() when input is not passed."""
        empty_notifier_config = {}
        self.assertRaises(InvalidInputError,
                          email_factory.EmailFactory(
                              empty_notifier_config).get_connector)
