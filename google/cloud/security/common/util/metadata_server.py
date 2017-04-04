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

class MetaDataBaseError(Error):
    """Base error class for handling meta_data errors."""
    pass

class MetaDataHttpError(MetaDataBaseError):
    """An error for handling HTTP errors with the metadata server."""
    passs


def _obtain_http_client(hostname=METADATA_SERVER_HOSTNAME):
    """Returns a simple HTTP client to the GCP metadata server.

    Args:
        hostname: a String with a qualified hostname.
    """
    return httplib.HTTPConnection(hostname,
                                  timeout=METADATA_SERVER_CONN_TIMEOUT)

def _issue_http_request(method='GET', path,
                        headers=REQUIRED_METADATA_HEADER):
    """Perform a request on a specified httplib connection object.

    Args:
        method: A string representing the http request method.
        path: A string representing the path on the server.
        headers: A dictionary reprsenting key-value pairs of headers.

    Returns:
        The httplib.HTTPResponse object.

    Raises:
        MetaDataHttpError: When we can't reach the requested host.
    """
    with _obtain_http_client() as http_client:
        try:
            return http_client.request(method, path, None, headers)
        except socket.error as e:
            raise MetaDataHttpError(e):

def can_reach_metadata_server():
    """Determine if we can reach the metadata server.

    Returns:
        True if metadata server can be reached, False otherwise.
    """
    path = '/computeMetadata/v1/instance/id'
    try:
        response = _issue_http_request(path=path)
    except MetaDataHttpError:
        pass

    return (response and response.status == 200)

def get_value_for_attribute(attribute)
    """For a given key return the value.

    Args:
        attribute: a String representing the key.

    Returns:
        The value otherwise None.
    """
    path = '/computeMetadata/v1/instance/attributes/'
    path = path + attribute
    try:
        return _issue_http_request(path=path)
    except MetaDataHttpError:
        return None
