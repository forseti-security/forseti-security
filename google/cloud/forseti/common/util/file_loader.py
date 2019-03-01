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

"""Utility functions for reading and parsing files in a variety of formats."""

import json
import os
import tempfile
import yaml

from google.cloud.forseti.common.gcp_api import storage
from google.cloud.forseti.common.util import errors as util_errors
from google.cloud.forseti.common.util import logger


LOGGER = logger.get_logger(__name__)


def read_and_parse_file(file_path):
    """Parse a json or yaml formatted file from a local path or GCS.

    Args:
        file_path (str): The full path to the file to read and parse.

    Returns:
        dict: The results of parsing the file.
    """
    file_path = file_path.strip()

    if file_path.startswith('gs://'):
        return _read_file_from_gcs(file_path)

    return _read_file_from_local(file_path)


def copy_file_from_gcs(file_path, output_path=None, storage_client=None):
    """Copy file from GCS to local file.

     Args:
        file_path (str): The full GCS path to the file.
        output_path (str): The local file to copy to, if not set creates a
            temporary file.
        storage_client (storage.StorageClient): The Storage API Client to use
            for downloading the file using the API.

     Returns:
        str: The output_path the file was copied to.
    """
    if not storage_client:
        storage_client = storage.StorageClient()

    if not output_path:
        tmp_file, output_path = tempfile.mkstemp()
        # Ensure the handle returned by mkstemp is not leaked.
        os.close(tmp_file)

    with open(output_path, mode='wb') as f:
        storage_client.download(full_bucket_path=file_path, output_file=f)

    return output_path


def _get_filetype_parser(file_path, parser_type):
    """Return a parser function for parsing the file.

    Args:
        file_path (str): The file path.
        parser_type (str): The file parser type.

    Returns:
        function: The parser function.
    """
    filetype_handlers = {
        'json': {
            'string': _parse_json_string,
            'file': _parse_json_file
        },
        'yaml': {
            'string': _parse_yaml,
            'file': _parse_yaml
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


def _read_file_from_gcs(file_path, storage_client=None):
    """Load file from GCS.

    Args:
        file_path (str): The GCS path to the file.
        storage_client (storage.StorageClient): The Storage API Client to use
            for downloading the file using the API.

    Returns:
        dict: The parsed dict from the loaded file.
    """
    if not storage_client:
        storage_client = storage.StorageClient()

    file_content = storage_client.get_text_file(full_bucket_path=file_path)

    parser = _get_filetype_parser(file_path, 'string')
    return parser(file_content)


def _read_file_from_local(file_path):
    """Load rules file from local path.

    Args:
      file_path (str): The path to the file.

    Returns:
        dict: The parsed dict from the loaded file.
    """
    with open(os.path.abspath(file_path), 'r') as rules_file:
        parser = _get_filetype_parser(file_path, 'file')
        return parser(rules_file)


def _parse_json_string(data):
    """Parse the data from a string of json.

    Args:
        data (str): String data to parse into json.

    Returns:
        dict: The json string successfully parsed into a dict.

    Raises:
        ValueError: If there was an error parsing the data.
    """
    try:
        return json.loads(data)
    except ValueError as json_error:
        raise json_error


def _parse_json_file(data):
    """Parse the data from a json file.

    Args:
        data (filepointer): File-like object containing a Json document,
            to be parsed into json.

    Returns:
        dict: The file successfully parsed into a dict.

    Raises:
        ValueError: If there was an error parsing the file.
    """
    try:
        return json.load(data)
    except ValueError as json_error:
        raise json_error


def _parse_yaml(data):
    """Parse yaml data.

    Args:
        data (stream): A yaml data stream to parse.

    Returns:
        dict: The stream successfully parsed into a dict.

    Raises:
        YAMLError: If there was an error parsing the stream.
    """
    try:
        return yaml.safe_load(data)
    except yaml.YAMLError as yaml_error:
        LOGGER.exception(yaml_error)
        raise yaml_error
