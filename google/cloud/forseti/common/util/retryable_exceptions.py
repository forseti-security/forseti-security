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

"""Module to determine whether an exception should be retried."""

from future import standard_library
standard_library.install_aliases()
import http.client
import socket
import ssl
import urllib.request, urllib.error, urllib.parse
import httplib2

from google.cloud.forseti.scanner.scanners.config_validator_util import (
    errors as cv_errors
)


RETRYABLE_EXCEPTIONS = (
    http.client.ResponseNotReady,
    http.client.IncompleteRead,
    httplib2.ServerNotFoundError,
    socket.error,
    ssl.SSLError,
    urllib.error.URLError,  # include "no network connection"
)

CONFIG_VALIDATOR_EXCEPTIONS = (
    cv_errors.ConfigValidatorServerUnavailableError,
)


def is_retryable_exception(e):
    """Whether exception should be retried.

    Args:
        e (Exception): Exception object.

    Returns:
        bool: True for exceptions to retry. False otherwise.
    """
    return isinstance(e, RETRYABLE_EXCEPTIONS)


def is_retryable_exception_cv(e):
    """Whether exception should be retried for Config Validator communications.

    Args:
        e (Exception): Exception object.

    Returns:
        bool: True for exceptions to retry. False otherwise.
    """

    return isinstance(e, CONFIG_VALIDATOR_EXCEPTIONS)
