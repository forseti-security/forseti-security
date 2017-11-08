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

"""Tests for the config validator."""

import json
import mock
import unittest

import jsonschema
import yaml

from google.cloud.security.common.util import config_validator
from tests.unittest_utils import ForsetiTestCase


class ConfigValidatorTest(ForsetiTestCase):
    """Tests for the config validator utility."""

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    def test_validate_schema_load_fail(self, mock_json_load, mock_open):
        """Test validate() raises InvalidSchemaError when schema load fails."""
        mock_json_load.side_effect = ValueError
        with self.assertRaises(config_validator.InvalidSchemaError):
            config_validator.validate('junk', 'junk')

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('yaml.safe_load')
    def test_validate_config_load_fail(self,
                                       mock_yaml_load,
                                       mock_json_load,
                                       mock_open):
        """Test validate() raises ConfigLoadError when config load fails."""
        mock_yaml_load.side_effect = yaml.YAMLError
        mock_json_load.return_value = {}
        with self.assertRaises(config_validator.ConfigLoadError):
            config_validator.validate('junk', 'junk')

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('yaml.safe_load')
    @mock.patch('jsonschema.validate')
    def test_jsonschema_validationerror(self,
                                        mock_jsonschema_validate,
                                        mock_yaml_load,
                                        mock_json_load,
                                        mock_open):
        """Test validate() raises InvalidConfigError on json validation error."""
        mock_json_load.return_value = {}
        mock_yaml_load.return_value = {}
        mock_jsonschema_validate.side_effect = jsonschema.ValidationError('fail')
        with self.assertRaises(config_validator.InvalidConfigError):
            config_validator.validate('junk', 'junk')

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('yaml.safe_load')
    @mock.patch('jsonschema.validate')
    def test_jsonschema_schemaerror(self,
                                    mock_jsonschema_validate,
                                    mock_yaml_load,
                                    mock_json_load,
                                    mock_open):
        """Test validate() raises InvalidSchemaError on json validation error."""
        mock_json_load.return_value = {}
        mock_yaml_load.return_value = {}
        mock_jsonschema_validate.side_effect = jsonschema.SchemaError('fail')
        with self.assertRaises(config_validator.InvalidSchemaError):
            config_validator.validate('junk', 'junk')

    @mock.patch('__builtin__.open')
    @mock.patch('json.load')
    @mock.patch('yaml.safe_load')
    @mock.patch('jsonschema.validate')
    def test_validate_successful(self,
                                 mock_jsonschema_validate,
                                 mock_yaml_load,
                                 mock_json_load,
                                 mock_open):
        """Test validate() returns the config when validation passes."""
        mock_json_load.return_value = {}
        mock_yaml_load.return_value = {}
        mock_jsonschema_validate.side_effect = None
        self.assertEquals({}, config_validator.validate('', ''))


if __name__ == '__main__':
    unittest.main()
