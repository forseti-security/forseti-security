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

"""Metadata server utilities.

The metadata server is only accessible on GCE.
"""

import httplib
import socket


METADATA_SERVER_HOSTNAME = 'metadata.google.internal'
METADATA_SERVER_CONN_TIMEOUT = 2
REQUIRED_METADATA_HEADER = {'Metadata-Flavor': 'Google'}
HTTP_SUCCESS = httplib.OK
HTTP_GET = 'GET'


class MetadataBaseError(Exception):
    """Base error class for handling meta_data errors."""
    pass

class MetadataHttpError(MetadataBaseError):
    """An error for handling HTTP errors with the metadata server."""
    pass

def _obtain_http_client(hostname=METADATA_SERVER_HOSTNAME):
    """Returns a simple HTTP client to the GCP metadata server.

    Args:
        hostname: a String with a qualified hostname.
    """
    return httplib.HTTPConnection(hostname,
                                  timeout=METADATA_SERVER_CONN_TIMEOUT)

def _issue_http_request(path, method, headers):
    """Perform a request on a specified httplib connection object.

    Args:
        method: A string representing the http request method.
        path: A string representing the path on the server.
        headers: A dictionary reprsenting key-value pairs of headers.

    Returns:
        The httplib.HTTPResponse object.

    Raises:
        MetadataHttpError: When we can't reach the requested host.
    """
    http_client = _obtain_http_client()

    try:
        return http_client.request(path, method, headers)
    except socket.error as e:
        raise MetadataHttpError(e)
    finally:
      http_client.close()

def can_reach_metadata_server():
    """Determine if we can reach the metadata server.

    Returns:
        True if metadata server can be reached, False otherwise.
    """
    path = '/computeMetadata/v1/instance/id'
    response = None

    try:
        response = _issue_http_request(
            path, HTTP_GET, REQUIRED_METADATA_HEADER)
    except MetadataHttpError as e:
        pass

    return (response and response.status == HTTP_SUCCESS)

def get_value_for_attribute(attribute):
    """For a given key return the value.

    Args:
        attribute: a String representing the key.

    Returns:
        The value of the request.
    """
    path = '/computeMetadata/v1/instance/attributes/'
    path = path + attribute
    http_response = ''

    try:
        http_response = _issue_http_request(
            path, HTTP_GET, REQUIRED_METADATA_HEADER)
        return http_response.read()
    except MetadataHttpError:
        return http_response
