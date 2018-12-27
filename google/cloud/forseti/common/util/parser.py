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

"""Utility functions for parsing various data."""

import json

from dateutil import parser as dateutil_parser

from google.cloud.forseti.common.util import logger

LOGGER = logger.get_logger(__name__)


def parse_member_info(member):
    """Parse out the components of an IAM policy binding member.

    Args:
        member (str): An IAM policy member, of the format
            "{membertype}:{email address}".

    Returns:
        str: The member type.
        str: The name portion of the member.
        str: The domain of the member.
    """
    member_type, email = member.split(':', 1)

    if '@' in email:
        member_name, member_domain = email.split('@', 1)
    else:
        # Member is really something like domain:google.com
        member_name = ''
        member_domain = email

    return member_type, member_name, member_domain


def format_timestamp(timestamp_str, datetime_formatter):
    """Parse and stringify a timestamp to a specified format.

    Args:
        timestamp_str (str): A timestamp.
        datetime_formatter (str): A format string.

    Returns:
        str: The formatted, stringified timestamp.
    """
    try:
        if '"' in timestamp_str or '\'' in timestamp_str:
            # Make sure the timestamp is not surrounded by any quotes
            timestamp_str = timestamp_str.replace('"', '')
            timestamp_str = timestamp_str.replace('\'', '')
        formatted_timestamp = (
            dateutil_parser.parse(timestamp_str).strftime(datetime_formatter))
    except (TypeError, ValueError) as e:
        LOGGER.warn('Unable to parse/format timestamp: %s\n,'
                    ' datetime_formatter: %s\n%s',
                    timestamp_str, datetime_formatter, e)
        formatted_timestamp = None
    return formatted_timestamp


def json_stringify(obj_to_jsonify):
    """Convert a python object to json string.

    Args:
        obj_to_jsonify (dict): The object to json stringify.

    Returns:
        str: The json-stringified dict.
    """
    # TODO: We should probably try and catch something here.
    return json.dumps(obj_to_jsonify, sort_keys=True)


def json_unstringify(json_to_objify, default=None):
    """Convert a json string to a python object.

    Args:
        json_to_objify (str): The json string.
        default (object): The default value if no json string is passed in.

    Returns:
        object: The un-stringified object.
    """
    try:
        parsed = json.loads(json_to_objify)
    except (TypeError, ValueError):
        parsed = default

    if parsed is None and default is not None:
        return default
    return parsed
