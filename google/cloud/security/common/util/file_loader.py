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

"""Utility functions for reading and parsing files in a variety of formats."""

import json
import os
import yaml

from google.cloud.security.common.gcp_api import storage
from google.cloud.security.common.util import errors as util_errors
from google.cloud.security.common.util import log_util

LOGGER = log_util.get_logger(__name__)


def read_and_parse_file(file_path):
    """Parse a json or yaml formatted file from a local path or GCS.

    Args:
        file_path: The full path to the file to read and parse.
    """

    file_path = file_path.strip()

    if file_path.startswith('gs://'):
        return _read_file_from_gcs(file_path)
    else:
        return _read_file_from_local(file_path)


def _get_filetype_parser(file_path, parser_type):
    """Return a parser function for parsing the file."""
    filetype_handlers = {
        'json': {
            'string': _parse_json_string,
            'file': _parse_json_file
        },
        'yaml': {
            'string': _parse_yaml_string,
            'file': _parse_yaml_file
        }
    }

    file_ext = file_path.split('.')[-1]

    if file_ext not in filetype_handlers:
        raise util_errors.InvalidFileExtensionError(
            'Unsupported file type: {}'.format(file_ext))

    if parser_type not in filetype_handlers[file_ext]:
        raise util_errors.InvalidParserTypeError(
            'Unsupported parser type: {}'.format(parser_type))

    return filetype_handlers[file_ext][parser_type]


def _read_file_from_gcs(file_path):
    """Load file from GCS.

    Returns:
        The parsed dict from the loaded file.
    """
    storage_client = storage.StorageClient()

    file_content = storage_client.get_text_file(full_bucket_path=file_path)

    parser = _get_filetype_parser(file_path, 'string')
    return parser(file_content)


def _read_file_from_local(file_path):
    """Load rules file from local path.

    Returns:
        The parsed dict from the loaded file.
    """
    with open(os.path.abspath(file_path), 'r') as rules_file:
        parser = _get_filetype_parser(file_path, 'file')
        return parser(rules_file)


def _parse_json_string(data):
    """Parse the data from a string of json."""
    try:
        return json.loads(data)
    except ValueError as json_error:
        raise json_error


def _parse_json_file(data):
    """Parse the data from a json file."""
    try:
        return json.load(data)
    except ValueError as json_error:
        raise json_error


def _parse_yaml_string(data):
    """Parse the data from a string of yaml."""
    try:
        return yaml.safe_load(data)
    except yaml.YAMLError as yaml_error:
        LOGGER.error(yaml_error)
        raise yaml_error


def _parse_yaml_file(data):
    """Parse the data from a yaml file."""
    try:
        return yaml.load(data)
    except yaml.YAMLError as yaml_error:
        LOGGER.error(yaml_error)
        raise yaml_error
