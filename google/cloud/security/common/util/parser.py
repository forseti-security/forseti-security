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

"""Utility functions for parsing various data."""

import json

from dateutil import parser as dateutil_parser

from google.cloud.security.common.data_access import errors as da_errors
from google.cloud.security.common.util import log_util


# TODO: The next editor must remove this disable and correct issues.
# pylint: disable=missing-type-doc,missing-return-type-doc


LOGGER = log_util.get_logger(__name__)


def parse_member_info(member):
    """Parse out the component info in the member string.

    Args:
        member: String of a member.  Example: user:foo@bar.com

    Returns:
        member_type: String of the member type.
        member_name: String of the name portion of the member.
        member_domain: String of the domain of the member.
    """
    member_type, email = member.split(":", 1)

    if '@' in email:
        member_name, member_domain = email.split('@', 1)
    else:
        # Member then is really something like domain:google.com
        member_name = ''
        member_domain = email

    return member_type, member_name, member_domain

def format_timestamp(timestamp_str, datetime_formatter):
    """Parse and stringify a timestamp to a specified format.

    Args:
        timestamp_str: A string timestamp.
        datetime_formatter: A string format.

    Returns:
        The formatted stringified timestamp.
    """
    try:
        formatted_timestamp = (
            dateutil_parser
            .parse(timestamp_str)
            .strftime(datetime_formatter))
    except (TypeError, ValueError) as e:
        LOGGER.warn('Unable to parse/format timestamp: %s\n%s',
                    timestamp_str, e)
        formatted_timestamp = None
    return formatted_timestamp

def json_stringify(obj_to_jsonify):
    """Convert a python object to json string.

    Args:
        obj_to_jsonify: The object to json stringify.

    Returns:
        The json-stringified dict.
    """
    try:
        json_str = json.dumps(obj_to_jsonify)
    except da_errors.Error:
        json_str = None
    return json_str
