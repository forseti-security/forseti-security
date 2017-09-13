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

"""Tests the api helpers functions."""

import unittest
import mock

from tests import unittest_utils
from tests.common.gcp_api.test_data import fake_key_file
from google.cloud.security.common.gcp_api import api_helpers
from google.cloud.security.common.gcp_api import errors as api_errors


class ApiHelpersTest(unittest_utils.ForsetiTestCase):
    """Test the Base Repository methods."""

    @mock.patch('oauth2client.crypt.Signer.from_string',
                return_value=object())
    def test_credential_from_keyfile(self, signer_factory):
        """Validate with a valid test credential file."""
        test_delegate = 'user@forseti.testing'
        with unittest_utils.create_temp_file(fake_key_file.FAKE_KEYFILE) as f:
            credentials = api_helpers.credential_from_keyfile(
                f, fake_key_file.FAKE_REQUIRED_SCOPES, test_delegate)
            self.assertEqual(credentials._kwargs['sub'], test_delegate)

    def test_credential_from_keyfile_raises(self):
        """Validate that an invalid credential file raises exception."""
        with unittest_utils.create_temp_file(b'{}') as f:
            with self.assertRaises(api_errors.ApiInitializationError):
                api_helpers.credential_from_keyfile(
                    f, fake_key_file.FAKE_REQUIRED_SCOPES,
                    'user@forseti.testing')


if __name__ == '__main__':
    unittest.main()
