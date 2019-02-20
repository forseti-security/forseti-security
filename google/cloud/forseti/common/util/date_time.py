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

import calendar
from datetime import datetime
from dateutil import parser

from google.cloud.forseti.common.util import logger
from google.cloud.forseti.common.util import string_formats

LOGGER = logger.get_logger(__name__)


class Error(Exception):
    """A Base UtilDateTime Exception."""


class DateTimeValueConversionError(Error):
    """Invalid Value Given for a Request."""


class DateTimeTypeConversionError(Error):
    """Type Error for a given Request."""


def get_datetime_from_string(string, string_format):
    """Get a datetime object from a string in the requested string_format.

        Args:
            string (str): The timestamp in the form of a string.
            string_format (str): A string used for formatting.

        Raises:
           DateTimeTypeConversionError: When datetime.strptime() raises a
              TypeError.
           DateTimeValueConversionError: When datetime.strptime() raises a
              ValueError.

        Returns:
            datetime: A datetime object as requested.
    """
    try:
        result = datetime.strptime(string, string_format)
    except TypeError:
        LOGGER.exception('Unable to create a datetime with %s in '
                         'format %s', string, string_format)
        raise DateTimeTypeConversionError
    except ValueError:
        LOGGER.exception('Unable to create a datetime with %s in '
                         'format %s', string, string_format)
        raise DateTimeValueConversionError

    return result


def get_unix_timestamp_from_string(string):
    """Parse string to a unix timestamp, as seconds since epoch.

    Args:
        string (str): The time string to parse.

    Returns:
        int: The timestamp in seconds.

    Raises:
        ValueError: Raised for unknown string formats.
    """
    date = parser.parse(string)
    return calendar.timegm(date.utctimetuple())


def get_utc_now_datetime():
    """Get a datetime object for utcnow()

    Returns:
          datetime: A datetime object representing utcnow().
    """
    return datetime.utcnow()


def get_utc_now_timestamp_human(date=None):
    """Get a human formatted str representing utcnow()

    Args:
        date (datetime): A datetime object representing current time in UTC.

    Returns:
          str: A timestamp in the classes default timestamp format.
    """
    utc_now = date or get_utc_now_datetime()
    return utc_now.strftime(string_formats.DEFAULT_FORSETI_HUMAN_TIMESTAMP)


def get_utc_now_timestamp(date=None):
    """Get a formatted str representing utcnow()

    Args:
        date (datetime): A datetime object representing current time in UTC.

    Returns:
          str: A timestamp in the classes default timestamp format.
    """
    utc_now = date or get_utc_now_datetime()
    return utc_now.strftime(string_formats.DEFAULT_FORSETI_TIMESTAMP)


def get_utc_now_unix_timestamp(date=None):
    """Get a 64bit int representing the current time to the millisecond.

    Args:
        date (datetime): A datetime object representing current time in UTC.

    Returns:
        int: A epoch timestamp including microseconds.
    """
    utc_now = date or get_utc_now_datetime()
    return calendar.timegm(utc_now.utctimetuple())


def get_utc_now_microtimestamp(date=None):
    """Get a 64bit int representing the current time to the millisecond.

    Args:
        date (datetime): A datetime object representing current time in UTC.

    Returns:
        int: A epoch timestamp including microseconds.
    """
    utc_now = date or get_utc_now_datetime()
    micros = calendar.timegm(utc_now.utctimetuple()) * 1000000
    return micros + utc_now.microsecond


def get_date_from_microtimestamp(microtimestamp):
    """Get a datetime object from a 64bit timestamp.

    Args:
        microtimestamp (int): A timestamp to be converted.

    Returns:
        datetime: The converted datetime object
    """
    return datetime.utcfromtimestamp(microtimestamp / float(1000000.0))
