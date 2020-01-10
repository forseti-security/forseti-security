# Copyright 2020 The Forseti Security Authors. All rights reserved.
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

import unittest.mock as mock
from unittest.mock import patch
from tests.unittest_utils import ForsetiTestCase
from google.cloud.forseti.scanner.scanners.config_validator_scanner import (
    ConfigValidatorScanner)
from google.cloud.forseti.scanner.scanners.config_validator_util import (
    errors)


class ConfigValidatorScannerTest(ForsetiTestCase):
    """Tests for the Config Validator Scanner."""

    def setUp(self):
        self.scanner = ConfigValidatorScanner({},
                                              {},
                                              mock.MagicMock(),
                                              'ScannerBuilderTestModel',
                                              '20201237T121212Z',
                                              '')

    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_verify_policy_library_empty_constraints_raises_exception(self,
                                                                      mock_isdir,
                                                                      mock_listdir):
        mock_isdir.side_effect = [True, True, True]
        mock_listdir.side_effect = [[], ['file1']]
        self.assertRaises(errors.ConfigValidatorPolicyLibraryError, self.scanner.verify_policy_library)
        self.assertEqual(mock_listdir.call_count, 1)

    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_verify_policy_library_empty_lib_raises_exception(self,
                                                              mock_isdir,
                                                              mock_listdir):
        mock_isdir.side_effect = [True, True, True]
        mock_listdir.side_effect = [['file1'], []]
        self.assertRaises(errors.ConfigValidatorPolicyLibraryError, self.scanner.verify_policy_library)
        self.assertEqual(mock_listdir.call_count, 2)

    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_verify_policy_library_missing_constraints_raises_exception(self,
                                                                        mock_isdir,
                                                                        mock_listdir):
        mock_isdir.side_effect = [True, False, True]
        mock_listdir.side_effect = [['file1'], ['file1']]
        self.assertRaises(errors.ConfigValidatorPolicyLibraryError, self.scanner.verify_policy_library)
        self.assertEqual(mock_isdir.call_count, 2)

    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_verify_policy_library_missing_lib_raises_exception(self,
                                                                mock_isdir,
                                                                mock_listdir):
        mock_isdir.side_effect = [True, True, False]
        mock_listdir.side_effect = [['file1'], ['file1']]
        self.assertRaises(errors.ConfigValidatorPolicyLibraryError, self.scanner.verify_policy_library)
        self.assertEqual(mock_isdir.call_count, 3)

    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_verify_policy_library_missing_library_raises_exception(self,
                                                                    mock_isdir,
                                                                    mock_listdir):
        mock_isdir.side_effect = [False, True, True]
        mock_listdir.side_effect = [['file1'], ['file1']]
        self.assertRaises(errors.ConfigValidatorPolicyLibraryError, self.scanner.verify_policy_library)
        self.assertEqual(mock_isdir.call_count, 1)

    @patch('os.listdir')
    @patch('os.path.isdir')
    def test_verify_policy_library_success(self, mock_isdir, mock_listdir):
        mock_listdir.side_effect = [['file1'], ['file1']]
        mock_isdir.side_effect = [True, True, True]
        self.scanner.verify_policy_library()
        self.assertEqual(mock_listdir.call_count, 2)
        self.assertEqual(mock_isdir.call_count, 3)
