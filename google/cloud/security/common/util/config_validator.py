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
"""

import json
import os

import jsonschema
import yaml


def validate(config_path, schema_path):
    """Validate the configuration.

    Args:
        config_path (str): The filesystem path to the configuration.
        schema_path (str): The filesystem path to the schema.

    Returns:
        dict: The config that has been validated against the schema.

    Raises:
        ConfigLoadError: When the configuration load fails.
        InvalidConfigError: When the configuration does not
            validate correctly against the schema.
        InvalidSchemaError: When the schema is invalid.
    """
    with open(os.path.abspath(schema_path), 'rb') as fp:
        try:
            schema = json.load(fp)
        except ValueError as ve:
            raise InvalidSchemaError(ve)

    with open(os.path.abspath(config_path), 'rb') as fp:
        try:
            config = yaml.safe_load(fp)
        except yaml.YAMLError as yaml_error:
            raise ConfigLoadError(yaml_error)

    try:
        jsonschema.validate(config, schema)
    except jsonschema.ValidationError as ve:
        raise InvalidConfigError(ve)
    except jsonschema.SchemaError(se):
        raise InvalidSchemaError(se)

    return config


# TODO: custom messaging for errors?

class Error(Exception):
    """Base Error class."""


class ConfigLoadError(Error):
    """ConfigLoadError."""


class InvalidConfigError(Error):
    """InvalidConfigError."""


class InvalidSchemaError(Error):
    """InvalidSchemaError."""
