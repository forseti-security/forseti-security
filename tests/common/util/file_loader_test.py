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

"""Tests the file loader utility."""

import json

import mock
import unittest
import yaml

from tests.unittest_utils import ForsetiTestCase
from tests.common.gcp_api.test_data import http_mocks
from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util import file_loader
from google.cloud.security.common.util import errors

from StringIO import StringIO


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

    def test_read_file_from_gcs_json(self):
        """Test read_file_from_gcs for json."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-10/11'}, b'{"test": 1}')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)
        expected_dict = {"test": 1}
        return_dict = file_loader._read_file_from_gcs('gs://fake/file.json')

        self.assertEqual(expected_dict, return_dict)

    def test_read_file_from_gcs_yaml(self):
        """Test read_file_from_gcs for yaml."""
        mock_responses = [
            ({'status': '200',
              'content-range': '0-6/7'}, b'test: 1')
        ]
        http_mocks.mock_http_response_sequence(mock_responses)
        expected_dict = {"test": 1}
        return_dict = file_loader._read_file_from_gcs('gs://fake/file.yaml')

        self.assertEqual(expected_dict, return_dict)

    def test_raise_on_json_string_error(self):
        """Test raise error on json string error."""
        with self.assertRaises(ValueError):
            file_loader._parse_json_string('')


if __name__ == '__main__':
    unittest.main()

