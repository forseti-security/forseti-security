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

import httplib
import socket
import ssl
import urllib2

import httplib2


RETRYABLE_EXCEPTIONS = (
    httplib.ResponseNotReady,
    httplib.IncompleteRead,
    httplib2.ServerNotFoundError,
    socket.error,
    ssl.SSLError,
    urllib2.URLError,  # include "no network connection"
)


def is_retryable_exception(e):
    """Whether exception should be retried.

    Args:
        e (Exception): Exception object.

    Returns:
        bool: True for exceptions to retry. False otherwise.
    """
    return isinstance(e, RETRYABLE_EXCEPTIONS)
