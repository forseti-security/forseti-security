# Copyright 2019 The Forseti Security Authors. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-1.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Test http_helpers utility functions."""

import httplib2
import unittest.mock as mock
import unittest

from google.cloud.forseti.common.util import http_helpers
from test.unittest_utils import ForsetiTestCase


DUMMY_URL = "http://127.0.0.1"
UA_KEY = "user-agent"


class MockResponse(object):
    def __iter__(self):
        yield self
        yield b''


class MockHttp(object):
    def __init__(self):
        self.headers = {}

    def request(self, uri, method='GET', body=None, headers=None,
                redirections=httplib2.DEFAULT_MAX_REDIRECTS,
                connection_type=None):
        self.headers = headers
        return MockResponse()


class HttpHelpersTest(ForsetiTestCase):
    """Test http_helpers utility functions."""

    def test_without_suffix(self):
        http_helpers.set_user_agent_suffix("")
        mock_http = MockHttp()
        http = http_helpers.build_http(mock_http)
        response, content = http.request(DUMMY_URL)
        self.assertIn(UA_KEY, mock_http.headers)
        self.assertRegex(
            mock_http.headers[UA_KEY], r'forseti-security/[0-9.]+$')

    def test_with_suffix(self):
        http_helpers.set_user_agent_suffix("foobar")
        mock_http = MockHttp()
        http = http_helpers.build_http(mock_http)
        response, content = http.request(DUMMY_URL)
        self.assertIn(UA_KEY, mock_http.headers)
        self.assertRegex(
            mock_http.headers[UA_KEY], r'foobar$')


if __name__ == '__main__':
    unittest.main()
