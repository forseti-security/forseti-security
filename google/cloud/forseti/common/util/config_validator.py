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

"""Configuration Validator.

This is a wrapper around the jsonschema validator.

validate() reads in the yaml configuration as a dict and the schema
(should be a valid json file, see http://json-schema.org/) as a dict,
then tries to validate the config against the schema.
"""

import json
import os

import jsonschema
import yaml


def validate(config_path, schema_path):
    """Validate the configuration.

    Args:
        config_path (str): The filesystem path to a yaml configuration.
        schema_path (str): The filesystem path to the schema.

    Returns:
        dict: The config that has been validated against the schema.

    Raises:
        ConfigLoadError: When the configuration load fails.
        InvalidConfigError: When the configuration does not
            validate correctly against the schema.
        InvalidSchemaError: When the schema is invalid.
    """
    with open(os.path.abspath(schema_path), 'rb') as filep:
        try:
            schema = json.load(filep)
        except ValueError as verr:
            raise InvalidSchemaError(verr)

    with open(os.path.abspath(config_path), 'rb') as filep:
        try:
            config = yaml.safe_load(filep)
        except yaml.YAMLError as yaml_error:
            raise ConfigLoadError(yaml_error)

    try:
        jsonschema.validate(config, schema)
    except jsonschema.ValidationError as verr:
        raise InvalidConfigError(verr)
    except jsonschema.SchemaError as serr:
        raise InvalidSchemaError(serr)

    return config


class Error(Exception):
    """Base Error class."""


class ConfigLoadError(Error):
    """ConfigLoadError."""


class InvalidConfigError(Error):
    """InvalidConfigError."""


class InvalidSchemaError(Error):
    """InvalidSchemaError."""
