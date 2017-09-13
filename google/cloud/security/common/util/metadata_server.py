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

"""Metadata server utilities.

The metadata server is only accessible on GCE.
"""

import httplib
import socket

from google.cloud.security.common.util import errors
from google.cloud.security.common.util import log_util


METADATA_SERVER_HOSTNAME = 'metadata.google.internal'
METADATA_SERVER_CONN_TIMEOUT = 2
REQUIRED_METADATA_HEADER = {'Metadata-Flavor': 'Google'}
HTTP_SUCCESS = httplib.OK
HTTP_GET = 'GET'

LOGGER = log_util.get_logger(__name__)


def _obtain_http_client(hostname=METADATA_SERVER_HOSTNAME):
    """Get an HTTP client to the GCP metadata server.

    Args:
        hostname (str): A qualified hostname.

    Returns:
        HttpClient: A simple HTTP client to the GCP metadata server.
    """
    return httplib.HTTPConnection(hostname,
                                  timeout=METADATA_SERVER_CONN_TIMEOUT)

def _issue_http_request(path, method, headers):
    """Perform a request on a specified httplib connection object.

    Args:
        method (str): The http request method.
        path (str): The path on the server.
        headers (dict): A key-value pairs of headers.

    Returns:
        httplib.HTTPResponse: The HTTP response object.

    Raises:
        MetadataServerHttpError: When we can't reach the requested host.
    """
    http_client = _obtain_http_client()

    try:
        return http_client.request(path, method, headers)
    except socket.error:
        raise errors.MetadataServerHttpError
    finally:
        http_client.close()

# TODO: Should use memoize or similar so that after the first check
# the cached result is always returned, regardless of how often it is
# called.
def can_reach_metadata_server():
    """Determine if we can reach the metadata server.

    Returns:
        bool: True if metadata server can be reached, False otherwise.
    """
    path = '/computeMetadata/v1/instance/id'
    response = None

    try:
        response = _issue_http_request(
            path, HTTP_GET, REQUIRED_METADATA_HEADER)
    except errors.MetadataServerHttpError:
        pass

    return response and response.status == HTTP_SUCCESS

def get_value_for_attribute(attribute):
    """For a given key return the value.

    Args:
        attribute (str): Some metadata key.

    Returns:
        str: The value of the requested key, if key isn't present then None.
    """
    path = '/computeMetadata/v1/instance/attributes/%s' % attribute
    try:
        http_response = _issue_http_request(
            path, HTTP_GET, REQUIRED_METADATA_HEADER)
        read_response = http_response.read()

        return read_response
    except (TypeError, ValueError,
            errors.MetadataServerHttpError) as e:
        LOGGER.error('Unable to read value for attribute key %s '
                     'from metadata server: %s', attribute, e)
        return None
