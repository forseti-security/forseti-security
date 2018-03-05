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

"""Common utility functions regarding date and time."""

from datetime import datetime

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats

LOGGER = logger.get_logger(__name__)


class UtilBaseDateTimeException(Exception):
    """A Base UtilDateTime Exception."""


class UtilDateTimedValueError(UtilBaseDateTimeException):
    """Invalid Value Given for a Request."""


class UtilDateTimeTypeError(UtilBaseDateTimeException):
    """Type Error for a given Request."""


def get_datetime_from_string(string, string_format):
    """Get a datetime object from a string in the requested string_format.

        Args:
            string (str): The timestamp in the form of a string.
            string_format (str): A string used for formatting.

        Raises:
           UtilDateTimeTypeError: When datetime.strptime() raises a TypeError.
           UtilDateTimeValueErro: When datetime.strptime() raises a ValueError.

        Returns:
            datetime: A datetime object as requested.
    """
    try:
        result = datetime.strptime(string, string_format)
    except TypeError:
        LOGGER.error('Unable to create a datetime with %s in format %s',
                     string, string_format)
        raise UtilDateTimeTypeError
    except ValueError:
        LOGGER.error('Unable to create a datetime with %s in format %s',
                     string, string_format)
        raise UtilDateTimedValueError

    return result


def get_utc_now_datetime():
    """Get a datetime object for utcnow()

    Returns:
          datetime: A datetime object representing utcnow().
    """
    return datetime.utcnow()


def get_utc_now_timestamp_human():
    """Get a human formatted str representing utcnow()

    Returns:
          str: A timestamp in the classes default timestamp format.
    """
    utc_now = get_utc_now_datetime()
    return utc_now.strftime(string_formats.DEFAULT_FORSETI_HUMAN_TIMESTAMP)


def get_utc_now_timestamp():
    """Get a formatted str representing utcnow()

    Returns:
          str: A timestamp in the classes default timestamp format.
    """
    utc_now = get_utc_now_datetime()
    return utc_now.strftime(string_formats.DEFAULT_FORSETI_TIMESTAMP)
