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

"""Tests the file loader utility."""

import os
import unittest
import mock
import google.auth
from google.oauth2 import credentials

from tests.common.gcp_api.test_data import http_mocks
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.common.util import errors
from google.cloud.forseti.common.util import file_loader


class FileLoaderTest(ForsetiTestCase):
    """Test the file loader utility."""

    def test_get_filetype_parser_works(self):
        """Test get_filetype_parser() works."""
        self.assertIsNotNone(
            file_loader._get_filetype_parser('file.yaml', 'string'))
        self.assertIsNotNone(
            file_loader._get_filetype_parser('file.yaml', 'file'))
        self.assertIsNotNone(
            file_loader._get_filetype_parser('file.json', 'string'))
        self.assertIsNotNone(
            file_loader._get_filetype_parser('file.json', 'file'))

    def test_get_filetype_parser_raises_errors_for_invalid_ext(self):
        """Test get_filetype_parser() raises error for invalid extension."""
        with self.assertRaises(errors.InvalidFileExtensionError):
            file_loader._get_filetype_parser('invalid/path', 'string')

    def test_get_filetype_parser_raises_errors_for_invalid_parser(self):
        """Test get_filetype_parser() raises error for invalid parser."""
        with self.assertRaises(errors.InvalidParserTypeError):
            file_loader._get_filetype_parser('path/to/file.yaml', 'asdf')

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_read_file_from_gcs_json(self, mock_default_credential):
        """Test read_file_from_gcs for json."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-10/11'}, b'{"test": 1}')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)
        expected_dict = {'test': 1}
        return_dict = file_loader._read_file_from_gcs('gs://fake/file.json')

        self.assertEqual(expected_dict, return_dict)

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_read_file_from_gcs_yaml(self, mock_default_credential):
        """Test read_file_from_gcs for yaml."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-6/7'}, b'test: 1')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)
        expected_dict = {'test': 1}
        return_dict = file_loader._read_file_from_gcs('gs://fake/file.yaml')

        self.assertEqual(expected_dict, return_dict)

    def test_raise_on_json_string_error(self):
        """Test raise error on json string error."""
        with self.assertRaises(ValueError):
            file_loader._parse_json_string('')

    @mock.patch.object(
        google.auth, 'default',
        return_value=(mock.Mock(spec_set=credentials.Credentials),
                      'test-project'))
    def test_copy_file_from_gcs(self, mock_default_credentials):
        """Test copying file from GCS works."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-10/11'}, b'{"test": 1}')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)
        try:
            file_path = file_loader.copy_file_from_gcs('gs://fake/file.json')
            with open(file_path, 'rb') as f:
                self.assertEqual(b'{"test": 1}', f.read())
        finally:
            os.unlink(file_path)

if __name__ == '__main__':
    unittest.main()
