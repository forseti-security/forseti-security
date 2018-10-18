# Copyright 2018 The Forseti Security Authors. All rights reserved.
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
"""Helpers for httplib2.Http module."""
import httplib2
from google.cloud import forseti as forseti_security

# Per request max wait timeout.
HTTP_REQUEST_TIMEOUT = 30.0


def build_http(http=None):
    """Set custom Forseti user agent and timeouts on a new http object.

    Args:
        http (object): An instance of httplib2.Http, or compatible, used for
            testing.

    Returns:
        httplib2.Http: An http object with the forseti user agent set.
    """
    if not http:
        http = httplib2.Http(timeout=HTTP_REQUEST_TIMEOUT)
    user_agent = 'Python-httplib2/{} (gzip), {}/{}'.format(
        httplib2.__version__,
        forseti_security.__package_name__,
        forseti_security.__version__)

    return set_user_agent(http, user_agent)


def set_user_agent(http, user_agent):
    """Set the user-agent on every request.

    Args:
        http (object): An instance of httplib2.Http
            or something that acts like it.
        user_agent (string): The value for the user-agent header.

    Returns:
        httplib2.Http: A modified instance of http that was passed in.
    """
    if getattr(http, '_user_agent_set', False):
        return http
    setattr(http, '_user_agent_set', True)

    request_orig = http.request

    # pylint: disable=missing-param-doc, missing-type-doc
    # The closure that will replace 'httplib2.Http.request'.
    def new_request(uri, method='GET', body=None, headers=None,
                    redirections=httplib2.DEFAULT_MAX_REDIRECTS,
                    connection_type=None):
        """Modify the request headers to add the user-agent.

        Returns:
            tuple: (httplib2.Response, string) the Response object and the
                response content.
        """
        if headers is None:
            headers = {}
        headers['user-agent'] = user_agent
        resp, content = request_orig(uri, method, body, headers,
                                     redirections, connection_type)
        return resp, content
    # pylint: enable=missing-param-doc, missing-type-doc

    http.request = new_request
    return http
